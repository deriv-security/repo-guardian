"""
GitHub Continuous User Scanner

This script monitors GitHub repositories of organization members for changes
and scans for potential secrets using TruffleHog.
"""

import os
import pathlib
import json
import yaml
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from slack_sdk.webhook import WebhookClient

from github.client import GitHubClient
from scanners.trufflehog import scan_updated_commits, scan_new_repositories, scan_new_branches
from utils.slack import send_secret_alerts, send_new_repository_alert
from utils.logger import setup_json_logging, log_info, log_error, log_warn

# Constants and configuration
ROOT_PATH = str(pathlib.Path(__file__).parent.resolve())
MAX_WORKERS = 10

def load_config():
    """
    Load configuration from environment variables and config file.
    
    Returns:
        tuple: (token, slack_webhook_url, organizations)
    """
    # Load environment variables
    load_dotenv(f"{ROOT_PATH}/configs/.env", override=True)
    
    token = os.getenv("GITHUB_TOKEN")
    slack_webhook_url = os.getenv("SLACK_WEBHOOK")
    
    # Load configuration from YAML
    with open(f"{ROOT_PATH}/configs/config.yaml", "r") as c:
        configs = yaml.safe_load(c)
        organizations = configs.get("organizations", [])
    
    return token, slack_webhook_url, organizations

def load_previous_scan():
    """
    Load results from the previous scan.
    
    Returns:
        dict: Previous scan results or empty dict if none found
    """
    try:
        previous_scans = sorted(os.listdir(f"{ROOT_PATH}/scan_results"), reverse=True)
        
        if previous_scans:
            log_info(f"Previous scan: {previous_scans[0]}", 
                    event_type="scan.repo_guardian.previous_scan_file")
            with open(f"{ROOT_PATH}/scan_results/{previous_scans[0]}/commit_hash.json", 'r') as file:
                return json.load(file)
        else:
            return {}
    except Exception as e:
        return {}

def create_scan_directory():
    """
    Create a directory for the current scan results.
    
    Returns:
        str: Path to the scan directory
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
    scan_dir = os.path.join(ROOT_PATH, "scan_results", timestamp)
    os.makedirs(scan_dir, exist_ok=True)
    return scan_dir

def fetch_all_members(github_client, organizations):
    """
    Fetch all members from the specified organizations.
    
    Args:
        github_client (GitHubClient): GitHub client instance
        organizations (list): List of organization names
        
    Returns:
        list: List of unique member logins
    """
    members = []
    for org in organizations:
        org_members = github_client.get_org_members(org)
        if org_members is None:
            log_warn(f"Failed to get members for organization: {org}", 
                    event_type="scan.repo_guardian.fetch_users")
            continue
        members.extend(org_members)
    
    # Remove duplicates
    return list(set(members))

def fetch_member_repositories(github_client, members):
    """
    Fetch repositories for all members using multithreading.
    
    Args:
        github_client (GitHubClient): GitHub client instance
        members (list): List of member logins
        
    Returns:
        dict: Dictionary of member repositories
    """
    log_info(f"🚀 Starting threaded repository fetch for {len(members)} members", 
            event_type="scan.repo_guardian.fetch_repositories")
    log_info(f"🔧 Using {MAX_WORKERS} worker threads", 
            event_type="scan.repo_guardian.multithread")
    
    current_scan_result = {}
    completed_count = 0
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all tasks
        futures = [executor.submit(github_client.fetch_single_user, member) for member in members]
        
        # Collect results as they complete
        for future in as_completed(futures):
            member, user_repos = future.result()
            completed_count += 1
            
            if user_repos is not None:
                current_scan_result[member] = user_repos
                percentage = (completed_count / len(members)) * 100
                log_info(f"📊 Progress: {completed_count}/{len(members)} ({percentage:.1f}%) - ✅ {member}", 
                        event_type="scan.repo_guardian.fetch_repositories")
            else:
                percentage = (completed_count / len(members)) * 100
                log_warn(f"📊 Progress: {completed_count}/{len(members)} ({percentage:.1f}%) - ⚠️ Skipped {member}", 
                        event_type="scan.repo_guardian.fetch_repositories")
    
    successful_users = len(current_scan_result)
    failed_users = len(members) - successful_users
    log_info(f"🎉 Threaded fetch completed: {successful_users} successful, {failed_users} failed", 
            event_type="scan.repo_guardian.fetch_repositories")
    
    return current_scan_result

def save_scan_results(scan_dir, current_scan, updated_commits, new_repos, new_branches):
    """
    Save scan results to files.
    
    Args:
        scan_dir (str): Path to the scan directory
        current_scan (dict): Current scan results
        updated_commits (dict): Updated commits
        new_repos (dict): New repositories
        new_branches (dict): New branches
    """
    with open(f"{scan_dir}/commit_hash.json", "w") as file:
        json.dump(current_scan, file, indent=4)
    
    with open(f"{scan_dir}/updated_commit.json", "w") as file:
        json.dump(updated_commits, file, indent=4)
    
    with open(f"{scan_dir}/new_repo.json", "w") as file:
        json.dump(new_repos, file, indent=4)
    
    with open(f"{scan_dir}/new_branch.json", "w") as file:
        json.dump(new_branches, file, indent=4)

def extract_repo_urls(new_repos):
    """
    Extract repository URLs from new repositories dictionary.
    
    Args:
        new_repos (dict): New repositories dictionary
        
    Returns:
        list: List of unique repository URLs
    """
    repo_urls = []
    for repository in new_repos:
        username, repo_name, _ = repository.split("::", 2)
        repo_url = f"https://github.com/{username}/{repo_name}"
        
        # Avoid duplicates (multiple branches in the same repo)
        if repo_url not in repo_urls:
            repo_urls.append(repo_url)
    
    return repo_urls

def run_trufflehog_scans(scan_dir, updated_commits, new_repos, new_branches):
    """
    Run TruffleHog scans on updated commits, new repositories, and new branches.
    
    Args:
        scan_dir (str): Path to the scan directory
        updated_commits (dict): Updated commits
        new_repos (dict): New repositories
        new_branches (dict): New branches
        
    Returns:
        list: Combined list of all findings
    """
    log_info("/--------------------Starting Trufflehog Scan--------------------/", 
            event_type="scan.repo_guardian.trufflehog.start")
    
    trufflehog_scan_dir = "trufflehog_scan_results"
    os.makedirs(os.path.join(scan_dir, trufflehog_scan_dir), exist_ok=True)
    
    all_findings = []
    
    # Scan updated commits
    if updated_commits:
        findings, raw_output = scan_updated_commits(updated_commits)
        all_findings.extend(findings)
        
        with open(f"{scan_dir}/{trufflehog_scan_dir}/updated_commit.json", "w") as file:
            json.dump(findings, file, indent=4)
        
        with open(f"{scan_dir}/{trufflehog_scan_dir}/updated_commit_raw.json", "w") as file:
            json.dump(raw_output, file, indent=4)
    
    # Scan new repositories
    repo_urls = extract_repo_urls(new_repos)
    if repo_urls:
        findings, raw_output = scan_new_repositories(repo_urls)
        all_findings.extend(findings)
        
        with open(f"{scan_dir}/{trufflehog_scan_dir}/new_repos.json", "w") as file:
            json.dump(findings, file, indent=4)
        
        with open(f"{scan_dir}/{trufflehog_scan_dir}/new_repos_raw.json", "w") as file:
            json.dump(raw_output, file, indent=4)
    
    # Scan new branches
    if new_branches:
        findings, raw_output = scan_new_branches(new_branches)
        all_findings.extend(findings)
        
        with open(f"{scan_dir}/{trufflehog_scan_dir}/new_branches.json", "w") as file:
            json.dump(findings, file, indent=4)
        
        with open(f"{scan_dir}/{trufflehog_scan_dir}/new_branches_raw.json", "w") as file:
            json.dump(raw_output, file, indent=4)
    
    log_info("/--------------------Completed Trufflehog Scan--------------------/", 
            event_type="scan.repo_guardian.trufflehog.complete")
    
    return all_findings, repo_urls

def main():
    """
    Main function to run the GitHub continuous user scanner.
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Monitor GitHub repositories of organization members for changes and scan for secrets'
    )
    parser.add_argument('--no-trufflehog', action='store_true', help='Disable trufflehog scan')
    args = parser.parse_args()
    
    # Load configuration
    token, slack_webhook_url, organizations = load_config()
    
    # Set up logging
    setup_json_logging(
        service_name="repo_guardian", 
        log_file=f"{ROOT_PATH}/repo_guardian_scanner.log"
    )
    
    # Create Slack webhook client
    slack_webhook = WebhookClient(slack_webhook_url)
    
    # Create GitHub client
    github_client = GitHubClient(token)
    
    # Load previous scan results
    previous_scan_result = load_previous_scan()
    
    # Create directory for current scan results
    scan_dir = create_scan_directory()
    
    # Fetch all members from organizations
    members = fetch_all_members(github_client, organizations)
    
    # Fetch repositories for all members
    current_scan_result = fetch_member_repositories(github_client, members)
    
    # Compare current scan with previous scan
    updated_commits, new_repos, new_branches = github_client.compare_commit_hash(
        current_scan_result, previous_scan_result
    )
    
    # Save scan results
    save_scan_results(scan_dir, current_scan_result, updated_commits, new_repos, new_branches)
    
    # Send notification for new repositories
    repo_urls = extract_repo_urls(new_repos)
    if repo_urls:
        send_new_repository_alert(slack_webhook, repo_urls)
    
    # Run TruffleHog scans if enabled
    if not args.no_trufflehog:
        all_findings, _ = run_trufflehog_scans(scan_dir, updated_commits, new_repos, new_branches)
        
        # Send Slack notifications for findings
        log_info("/--------------------Sending Slack Message--------------------/", 
                event_type="scan.repo_guardian.slack")
        
        send_secret_alerts(slack_webhook, all_findings)
        
        log_info("/--------------------Slack Message Sent--------------------/", 
                event_type="scan.repo_guardian.slack")

if __name__ == "__main__":
    main()
