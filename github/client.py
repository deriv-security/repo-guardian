"""
GitHub client for interacting with GitHub API and processing repository data.
"""

import requests
import time
import threading
import logging
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from utils.logger import log_info, log_warn, log_error

class GitHubClient:
    """
    GitHub client that handles all GitHub API interactions, data collection, and processing.
    """
    
    def __init__(self, token, graphql_url="https://api.github.com/graphql"):
        """
        Initialize the GitHub client.
        
        Args:
            token (str): GitHub API token
            graphql_url (str): GitHub GraphQL API URL
        """
        self.token = token
        self.graphql_url = graphql_url
        self._session = None
        self._session_lock = threading.Lock()
        self._rate_limit_lock = threading.Lock()
        self._remaining_requests = None
        self._reset_at_time = None
        self._error_backoff_until = None
    
    def get_session(self, max_workers=10, connection_multiplier=2.0):
        """
        Get or create a thread-safe requests session with retry configuration.
        
        Args:
            max_workers (int): Maximum number of worker threads
            connection_multiplier (float): Multiplier for connection pool size
            
        Returns:
            requests.Session: Configured session
        """
        with self._session_lock:
            if self._session is None:
                self._session = requests.Session()
                
                # Configure retry strategy for connection issues
                # This is mainly use to handle connection issues, status code errors/rate limit is being handle separately 
                # Rate limit and error status code in handled under run_graphql_query() 
                retry_strategy = Retry(
                    total=3,                    # Maximum number of retries
                    connect=3,                  # Retries for connection-related errors
                    read=3,                     # Retries for read timeouts
                    status=0,                   # Don't retry on HTTP status codes (we handle those)
                    backoff_factor=10,          # Wait 10s, 20s, 40s between retries
                    status_forcelist=[],        # Empty - we handle HTTP errors in our logic
                    allowed_methods=["POST"],   # Only retry POST requests
                    raise_on_status=False       # Don't raise exceptions on HTTP status codes
                )
                
                # Dynamic connection pool sizing
                pool_size = int(max_workers * connection_multiplier)  # 10 * 2 = 20 connections
                log_info(f"🔧 Configuring connection pool: {pool_size} connections for {max_workers} workers", 
                        event_type="scan.repo_guardian.requests")
                
                # Create HTTP adapter with retry strategy
                adapter = HTTPAdapter(
                    max_retries=retry_strategy,
                    pool_connections=1,         # Single domain (api.github.com)
                    pool_maxsize=pool_size,     # 2x worker count
                    pool_block=False           # Don't block if pool is exhausted
                )
                
                # Mount the adapter for HTTPS requests
                self._session.mount("https://", adapter)
                
                # Set default headers for the session
                self._session.headers.update({
                    "User-Agent": "python-requests/2.32.4", # Testing this to see if it resolved ('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))
                    "Connection": "keep-alive"
                })
                
            return self._session
    
    def run_graphql_query(self, query, variables=None):
        """
        Execute a GraphQL query against GitHub's API with enhanced connection reliability.
        
        Args:
            query (str): GraphQL query
            variables (dict, optional): Variables for the query
            
        Returns:
            dict: Query result or None on failure
        """
        
        # Triple protection - rate limits + universal error + connection reliability
        with self._rate_limit_lock:
            current_time = time.time()
            
            # Layer 1: Rate limit protection
            if self._remaining_requests is not None and self._remaining_requests < 15:
                if self._reset_at_time:
                    try:
                        # Parse resetAt: "2025-08-11T07:33:48Z"
                        dt = datetime.fromisoformat(self._reset_at_time.replace('Z', '+00:00'))
                        reset_timestamp = dt.timestamp()
                        sleep_time = max(0, reset_timestamp - current_time + 5)  # +5s buffer
                        
                        if sleep_time > 0:
                            thread_name = threading.current_thread().name
                            log_warn(f"🚨 [{thread_name}] RATE LIMIT LOCK: {self._remaining_requests} remaining. Sleeping {sleep_time:.1f}s", 
                                    event_type="scan.repo_guardian.multithread")
                            time.sleep(sleep_time)
                    except Exception as e:
                        log_error(
                            message=f"Error parsing reset time: {e}", 
                            event_type="scan.repo_guardian.multithread.error",
                            error_type="MultithreadingError",
                            error_message=str(e),
                            exc_info=True
                        )
            
            # Layer 2: Universal error backoff (proactive prevention)
            if self._error_backoff_until and current_time < self._error_backoff_until:
                sleep_time = self._error_backoff_until - current_time
                thread_name = threading.current_thread().name
                log_warn(f"🚨 [{thread_name}] ERROR BACKOFF: sleeping {sleep_time:.1f}s", 
                        event_type="scan.repo_guardian.rate_limit")
                time.sleep(sleep_time)
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        
        payload = {
            "query": query,
            "variables": variables or {}
        }
        
        try:
            # Layer 3: Session-based requests with automatic retry for connection issues
            session = self.get_session()
            response = session.post(
                self.graphql_url, 
                headers=headers, 
                json=payload,
                timeout=(10, 30)  # (connect_timeout, read_timeout)
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Success - clear any error backoff and update rate limits
                with self._rate_limit_lock:
                    self._error_backoff_until = None  # Clear any error backoff
                    if 'data' in result and 'rateLimit' in result['data']:
                        self._remaining_requests = result['data']['rateLimit'].get('remaining')
                        self._reset_at_time = result['data']['rateLimit'].get('resetAt')
                        
                        # Optional: Log rate limit status occasionally
                        if self._remaining_requests and self._remaining_requests % 100 == 0:
                            log_info(f"📊 Rate limit: {self._remaining_requests}/5000 remaining", 
                                    event_type="scan.repo_guardian.rate_limit")
                
                return result
            else:
                # ANY non-200 status - set universal backoff for ALL threads
                with self._rate_limit_lock:
                    self._error_backoff_until = time.time() + 120  # 2-minute backoff
                    thread_name = threading.current_thread().name
                    log_warn(f"🚨 [{thread_name}] GitHub API error {response.status_code}: All threads backing off for 120s\nResponse: {response.text}", 
                            event_type="scan.repo_guardian.invalid_status_code")
                
                return None
                
        except requests.exceptions.RequestException as e:
            # Connection errors after retries are exhausted
            thread_name = threading.current_thread().name
            log_error(
                message=f"🔌 [{thread_name}] Connection failed after retries: {e}", 
                event_type="scan.repo_guardian.requests.error",
                error_type="RequestError",
                error_message=str(e),
                exc_info=True
            )
            
            # Trigger universal backoff for persistent connection issues
            # Ensuring all the other ongoing threads pauses for a while if one of the thread fails persistently 
            with self._rate_limit_lock:
                self._error_backoff_until = time.time() + 60  # 1-minute backoff for connection issues
                log_warn(
                    message=f"🚨 [{thread_name}] Persistent connection issues: All threads backing off for 60s", 
                    event_type="scan.repo_guardian.multithread.backoff",
                )
            
            return None
    
    def get_org_members(self, org):
        """
        Fetch all members from github organizations using GraphQL.
        
        Args:
            org (str): Organization name
            
        Returns:
            list: List of member logins or None on failure
        """
        
        members = []
        has_next_page = True
        cursor = None
        
        # GraphQL query for organization members with pagination
        query = """
        query($org: String!, $cursor: String) {
          rateLimit {
            limit
            cost
            remaining
            resetAt
          }
          organization(login: $org) {
            membersWithRole(first: 100, after: $cursor) {
              pageInfo {
                hasNextPage
                endCursor
              }
              nodes {
                login
              }
            }
          }
        }
        """
        
        while has_next_page:
            variables = {
                "org": org,
                "cursor": cursor
            }
            
            result = self.run_graphql_query(query, variables)
            
            if not result:
                log_error(
                    message=f"Error fetching members for {org}: GraphQL query failed", 
                    event_type="scan.repo_guardian.requests.error",
                    error_type="GithubGraphql",
                    error_message="No members fetched",
                    exc_info=False
                )
                return None
            
            if "errors" in result:
                log_error(
                    message=f"Error fetching members for {org}:", 
                    event_type="scan.repo_guardian.requests.error",
                    error_type="GithubGraphql",
                    error_message=result["errors"],
                    exc_info=True
                )
                return None
            
            data = result.get("data", {})
            org_data = data.get("organization", {})
            members_data = org_data.get("membersWithRole", {})
            
            # Extract member logins
            for member in members_data.get("nodes", []):
                members.append(member["login"])
            
            # Check if there are more pages
            page_info = members_data.get("pageInfo", {})
            has_next_page = page_info.get("hasNextPage", False)
            cursor = page_info.get("endCursor", None)
        
        return members
    
    def fetch_repositories_commit_hash(self, login):
        """
        Fetch all repositories and their commit hashes for a given GitHub user with full pagination.
        
        Args:
            login (str): GitHub username
            
        Returns:
            dict: Repository data or None on failure
        """
        
        # Query for initial repository batch with branches
        repo_batch_query = """
        query($login: String!, $repoCursor: String) {
          rateLimit {
            limit
            cost
            remaining
            resetAt
          }
          user(login: $login) {
            repositories(first: 100, after: $repoCursor, isArchived: false, privacy: PUBLIC, ownerAffiliations: [OWNER]) {
              nodes {
                name
                url
                refs(refPrefix: "refs/heads/", first: 100) {
                  nodes {
                    name
                    target {
                      ... on Commit {
                        oid
                      }
                    }
                  }
                  pageInfo {
                    hasNextPage
                    endCursor
                  }
                }
              }
              pageInfo {
                hasNextPage
                endCursor
              }
            }
          }
        }
        """
        
        # Query for additional branches of a specific repository
        more_branches_query = """
        query($owner: String!, $repo: String!, $branchCursor: String) {
          rateLimit {
            limit
            cost
            remaining
            resetAt
          }
          repository(owner: $owner, name: $repo) {
            refs(refPrefix: "refs/heads/", first: 100, after: $branchCursor) {
              nodes {
                name
                target {
                  ... on Commit {
                    oid
                  }
                }
              }
              pageInfo {
                hasNextPage
                endCursor
              }
            }
          }
        }
        """
        
        all_repositories = []
        repo_cursor = None
        repo_has_next_page = True
        
        # OUTER LOOP: Repository pagination
        while repo_has_next_page:
            # Fetch batch of repositories
            repo_variables = {
                "login": login,
                "repoCursor": repo_cursor
            }
            
            batch_result = self.run_graphql_query(repo_batch_query, repo_variables)
            
            if not batch_result or "errors" in batch_result:
                log_error(
                    message=f"Error fetching repository batch: {batch_result}", 
                    event_type="scan.repo_guardian.requests.error",
                    error_type="GithubGraphql",
                    exc_info=False            
                )
                return None
            
            # Display rate limit info
            rate_limit = batch_result["data"]["rateLimit"]
            log_info(f"Rate limit: {rate_limit['remaining']}/{rate_limit['limit']} remaining", 
                    event_type="scan.repo_guardian.rate_limit")
            
            current_repos = batch_result["data"]["user"]["repositories"]["nodes"]
            repo_page_info = batch_result["data"]["user"]["repositories"]["pageInfo"]
            
            # INNER LOOP: Complete all branches for each repository in current batch
            for repo in current_repos:
                repo_name = repo["name"]
                
                # Phase 1: Complete all branches for this repository
                branch_cursor = repo["refs"]["pageInfo"]["endCursor"]
                branch_has_next_page = repo["refs"]["pageInfo"]["hasNextPage"]
                
                branch_count = len(repo["refs"]["nodes"])
                
                # Continue fetching branches until all are retrieved
                while branch_has_next_page:
                    branch_variables = {
                        "owner": login,
                        "repo": repo_name,
                        "branchCursor": branch_cursor
                    }
                    
                    branch_result = self.run_graphql_query(more_branches_query, branch_variables)
                    
                    if not branch_result or "errors" in branch_result:
                        log_error(
                            message=f"    Error fetching branches for {repo_name}: {branch_result}", 
                            event_type="scan.repo_guardian.requests.error",
                            error_type="GithubGraphql",
                            exc_info=False
                        )
                        break
                    
                    # Check if repository still exists
                    if not branch_result["data"]["repository"]:
                        break
                    
                    additional_branches = branch_result["data"]["repository"]["refs"]["nodes"]
                    branch_page_info = branch_result["data"]["repository"]["refs"]["pageInfo"]
                    
                    # Append additional branches to the repository
                    repo["refs"]["nodes"].extend(additional_branches)
                    branch_count += len(additional_branches)
                    
                    # Update pagination info
                    branch_has_next_page = branch_page_info["hasNextPage"]
                    branch_cursor = branch_page_info["endCursor"]
                
                # Update final pagination info for this repository
                repo["refs"]["pageInfo"] = {
                    "hasNextPage": False,
                    "endCursor": branch_cursor
                }
            
            # Add completed repositories to final list
            all_repositories.extend(current_repos)
            
            # Check if more repository batches exist
            repo_has_next_page = repo_page_info["hasNextPage"]
            repo_cursor = repo_page_info["endCursor"]
            
            log_info(f"Completed batch. Total repositories so far: {len(all_repositories)}", 
                    event_type="scan.repo_guardian.fetch_repositories")
        
        log_info(f"\n✅ Completed! Total repositories: {len(all_repositories)}", 
                event_type="scan.repo_guardian.fetch_repositories")
        total_branches = sum(len(repo["refs"]["nodes"]) for repo in all_repositories)
        log_info(f"✅ Total branches across all repositories: {total_branches}", 
                event_type="scan.repo_guardian.branch")
        
        # Return data in the same format as the original response
        return {
            "data": {
                "rateLimit": rate_limit,
                "user": {
                    "repositories": {
                        "nodes": all_repositories,
                        "pageInfo": {
                            "hasNextPage": False,
                            "endCursor": None
                        }
                    }
                }
            }
        }
    
    def fetch_single_user(self, member):
        """
        Thread-safe function for fetching user repositories.
        Returns tuple: (member, user_repos_data) or (member, None) on failure
        
        Args:
            member (str): GitHub username
            
        Returns:
            tuple: (member, user_repos_data) or (member, None) on failure
        """
        
        try:
            thread_name = threading.current_thread().name
            
            data = self.fetch_repositories_commit_hash(member)

            if not data or "errors" in data:
                log_warn(f"[{thread_name}] Failed to fetch data for {member}", 
                        event_type="scan.repo_guardian.fetch_repositories")
                return member, None

            # Process data independently (no shared state)
            user_repos = {}
            repositories = data["data"]["user"]["repositories"]["nodes"]
            
            for repository in repositories:
                repository_name = repository["name"]
                user_repos[repository_name] = {}
                for branch in repository["refs"]["nodes"]:
                    branch_name = branch["name"]
                    user_repos[repository_name][branch_name] = branch["target"]["oid"]

            repo_count = len(user_repos)
            branch_count = sum(len(branches) for branches in user_repos.values())
            log_info(f"[{thread_name}] ✅ Completed {member}: {repo_count} repositories, {branch_count} branches", 
                    event_type="scan.repo_guardian.fetch_repositories")
            
            return member, user_repos

        except Exception as e:
            thread_name = threading.current_thread().name
            log_error(
                message=f"[{thread_name}] ❌ Error processing {member}: {e}", 
                event_type="scan.repo_guardian.fetch_repository.error",
                error_type="fetch_repository",
                error_message=str(e),
                exc_info=True
            )
            return member, None
    
    def flatten_scan_data(self, scan_data):
        """
        Use to make comparison easier (less nested)

        Convert 
        ```
        user: {
            repo1: {
                branch1: commit_hash,
                branch2: commit_hash,
            },
            repo2: {
                branch1: commit_hash,
                branch2: commit_hash,
            }
        }
        ```
        to 
        
        ```
        user::repo::branch: commit_hash
        ```

        for easier comparison
        
        Args:
            scan_data (dict): Nested scan data
            
        Returns:
            dict: Flattened scan data
        """
        flatten_data = {}
        for user, repos in scan_data.items():
            for repo, branches in repos.items():
                for branch, commit_hash in branches.items():
                    key = f"{user}::{repo}::{branch}"
                    flatten_data[key] = commit_hash
        
        return flatten_data
    
    def compare_commit_hash(self, current_scan, previous_scan):
        """
        Compare current scan with previous scan to find changes.
        
        Args:
            current_scan (dict): Current scan data
            previous_scan (dict): Previous scan data
            
        Returns:
            tuple: (updated_commits, new_repositories, new_branches)
        """
        
        if not current_scan:
            return [], [], []

        flatten_current_scan = self.flatten_scan_data(current_scan)
        flatten_previous_scan = self.flatten_scan_data(previous_scan)

        # Pre-compute which repositories existed in previous scan
        previous_repositories = set()
        for key in flatten_previous_scan.keys():
            username, repository, branch = key.split('::', 2)
            previous_repositories.add(f"{username}::{repository}")

        updated_commits = {}
        new_repositories = {}
        new_branches = {}

        for current_key, current_commit_hash in flatten_current_scan.items():
            username, repository, branch = current_key.split('::', 2)
            previous_commit_hash = flatten_previous_scan.get(current_key, "")

            if previous_commit_hash == "":
                repo_key = f"{username}::{repository}"

                if repo_key not in previous_repositories:
                    log_info(f"New repository created: {repository}", 
                            event_type="scan.repo_guardian.fetch_repositories")
                    new_repositories[current_key] = current_commit_hash
                else:
                    log_info(f"New branch created: {repository} - {branch}", 
                            event_type="scan.repo_guardian.fetch_branch")
                    new_branches[current_key] = current_commit_hash
                continue
            
            if current_commit_hash != previous_commit_hash:
                updated_commits[current_key] = {
                    "current_commit_hash": current_commit_hash,
                    "previous_commit_hash": previous_commit_hash
                }
        
        return updated_commits, new_repositories, new_branches
