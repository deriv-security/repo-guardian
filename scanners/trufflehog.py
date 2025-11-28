"""
TruffleHog scanner module for detecting secrets in GitHub repositories.
"""

import json
import subprocess
from utils.logger import log_info, log_error

def scan(repo_url="", commit_hash="", branch_name="", since_commit=False, branch=False):
    """
    Run TruffleHog scan on a GitHub repository.
    
    Args:
        repo_url (str): URL of the GitHub repository
        commit_hash (str): Commit hash to scan from
        branch_name (str): Branch name to scan
        since_commit (bool): Whether to scan since a specific commit
        branch (bool): Whether to scan a specific branch
        
    Returns:
        tuple: (findings, raw_results) where findings is a list of formatted findings
               and raw_results is the raw TruffleHog output
    """
    if since_commit:
        log_info(f"Starting updated scan for {repo_url}", 
                event_type="scan.repo_guardian.trufflehog.since_commit")
        trufflehog_cmd = [
            'trufflehog',
            '--no-update',
            'git',
            f'{repo_url}',
            f'--branch={branch_name}',
            f'--since-commit={commit_hash[:10]}',
            '--only-verified',
            '--json'
        ]
    elif branch:
        log_info(f"Starting branch scan for {repo_url}", 
                event_type="scan.repo_guardian.trufflehog.branch")
        trufflehog_cmd = [
            'trufflehog',
            '--no-update',
            'git',
            f'{repo_url}',
            f'--branch={branch_name}',
            '--only-verified',
            '--json'
        ]
    else:
        log_info(f"Starting full scan for {repo_url}", 
                event_type="scan.repo_guardian.trufflehog.repository")
        trufflehog_cmd = [
            'trufflehog',
            '--no-update',
            'github',
            f'--repo={repo_url}',
            '--only-verified',
            '--json'
        ]
        
    jq_cmd = ['jq', '-s']

    # Run trufflehog and pipe to jq
    trufflehog_process = subprocess.Popen(
        trufflehog_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    jq_process = subprocess.Popen(
        jq_cmd,
        stdin=trufflehog_process.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    # Close trufflehog stdout to allow it to receive SIGPIPE
    trufflehog_process.stdout.close()
    
    # Get the output
    output, error = jq_process.communicate()
    
    # Wait for trufflehog to complete
    trufflehog_process.wait()
    trufflehog_stderr = trufflehog_process.stderr.read() if trufflehog_process.stderr else ""
    
    if jq_process.returncode != 0:
        log_error(
            message=f"jq command failed: {error}", 
            event_type="scan.repo_guardian.subprocess.error",
            error_type="subprocess_jq",
            error_message=str(error),
            exc_info=True
        )
        return [], []
        
    if trufflehog_process.returncode != 0:
        log_error(
            message=f"TruffleHog scan failed for {repo_url}", 
            event_type="scan.repo_guardian.subprocess.error",
            error_type="subprocess_trufflehog",
            error_message=f"TruffleHog stderr: {trufflehog_stderr}",
            exc_info=True
        )
        return [], []
    
    try:
        findings = []
        results = json.loads(output)
        log_info(f"TruffleHog scan completed for {repo_url}. Found {len(results)} results.", 
                event_type="scan.repo_guardian.trufflehog.complete")  

        if since_commit or branch:
            for result in results:
                detector_name = result.get("DetectorName")
                link = result["SourceMetadata"]["Data"]["Git"]["repository"]
                secret_commit_hash = result["SourceMetadata"]["Data"]["Git"]["commit"]
                finding = {
                    "detector_name": detector_name,
                    "link": link,
                    "repo_url": repo_url,
                    "branch": branch_name or "",
                    "commit": secret_commit_hash or ""
                }
                findings.append(finding)
            
        else:
            for result in results:
                detector_name = result.get("DetectorName")
                link = result["SourceMetadata"]["Data"]["Github"]["link"]
                finding = {
                    "detector_name": detector_name,
                    "link": link,
                    "repo_url": repo_url,
                    "branch": "",
                    "commit": ""
                }
                findings.append(finding)

        return findings, results
    except json.JSONDecodeError as e:
        log_error(
            message=f"Failed to parse JSON output: {e}", 
            event_type="scan.repo_guardian.json_decode.error",
            error_type="JSONDecodeError",
            error_message=str(e),
            exc_info=True
        )
        return [], []

def scan_updated_commits(updated_commits):
    """
    Scan repositories with updated commits.
    
    Args:
        updated_commits (dict): Dictionary of updated commits
        
    Returns:
        tuple: (findings, raw_results)
    """
    findings = []
    raw_results = []
    
    for repository, commit_hash in updated_commits.items():
        username, repo_name, branch_name = repository.split("::", 2)
        repo_url = f"https://github.com/{username}/{repo_name}"
        
        trufflehog_findings, raw_output = scan(
            repo_url=repo_url, 
            commit_hash=commit_hash["previous_commit_hash"], 
            branch_name=branch_name, 
            since_commit=True
        )
        
        findings.extend(trufflehog_findings)
        raw_results.extend(raw_output)
    
    return findings, raw_results

def scan_new_repositories(repo_urls):
    """
    Scan newly created repositories.
    
    Args:
        repo_urls (list): List of repository URLs
        
    Returns:
        tuple: (findings, raw_results)
    """
    findings = []
    raw_results = []
    
    for repo_url in repo_urls:
        trufflehog_findings, raw_output = scan(repo_url=repo_url)
        findings.extend(trufflehog_findings)
        raw_results.extend(raw_output)
    
    return findings, raw_results

def scan_new_branches(new_branches):
    """
    Scan newly created branches.
    
    Args:
        new_branches (dict): Dictionary of new branches
        
    Returns:
        tuple: (findings, raw_results)
    """
    findings = []
    raw_results = []
    
    for repository, commit_hash in new_branches.items():
        username, repo_name, branch_name = repository.split("::", 2)
        repo_url = f"https://github.com/{username}/{repo_name}"
        
        trufflehog_findings, raw_output = scan(
            repo_url=repo_url, 
            branch_name=branch_name, 
            branch=True
        )
        
        findings.extend(trufflehog_findings)
        raw_results.extend(raw_output)
    
    return findings, raw_results

def format_findings_for_notification(findings):
    """
    Format findings for Slack notification.
    
    Args:
        findings (list): List of findings
        
    Returns:
        list: List of formatted messages, each containing up to 5 findings
    """
    messages = []
    current_message = ""
    count = 0
    
    for finding in findings:
        detector_name = finding.get("detector_name")
        link = finding.get("link")
        username = finding.get("repo_url").split("/")[-2]
        repo_name = finding.get("repo_url").split("/")[-1]
        branch_name = finding.get("branch")
        commit_hash = finding.get("commit")
        
        finding_text = f"\n\nRepository Name: {username}/{repo_name}\nDetector: {detector_name}\nLink: {link}"
        
        if branch_name:
            finding_text += f"\nBranch Name: {branch_name}"
            
        if commit_hash:
            finding_text += f"\nCommit Hash: {commit_hash}"
        
        current_message += finding_text
        count += 1
        
        # Break into multiple messages to prevent truncation
        if count % 5 == 0:
            messages.append(current_message)
            current_message = ""
    
    # Add any remaining findings
    if current_message:
        messages.append(current_message)
    
    return messages
