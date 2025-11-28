"""
Slack notification utilities for sending alerts and messages.
"""

from utils.logger import log_info

def send_notification(webhook, title, msg, color="#FF0000"):
    """
    Send a notification to Slack.
    
    Args:
        webhook: Slack webhook client
        title (str): Title of the notification
        msg (str): Message content
        color (str): Color of the notification (default: red)
        
    Returns:
        dict: Response from Slack API
    """
    log_info("Sending slack message...", event_type="scan.repo_guardian.slack")

    response = webhook.send(
        text=title, 
        attachments=[
            {
                "color": color,
                "fields": [{"value": msg}], 
            }
        ]
    )

    log_info(f"Slack Response Status Code - {response.status_code}", 
            event_type="scan.repo_guardian.slack")
    log_info(f"Slack Response Body - {response.body}", 
            event_type="scan.repo_guardian.slack")
    
    return response

def send_secret_alerts(webhook, findings, batch_size=5):
    """
    Send alerts about detected secrets to Slack.
    
    Args:
        webhook: Slack webhook client
        findings (list): List of findings from TruffleHog scan
        batch_size (int): Number of findings per message
        
    Returns:
        bool: True if messages were sent, False if no findings
    """
    if not findings:
        log_info("Public User Repository Monitoring - No Secret Found", 
                event_type="alert.scan.repo_guardian.no_secret_found")
        return False
    
    # Group findings into batches
    batches = []
    current_batch = []
    
    for idx, finding in enumerate(findings, start=1):
        current_batch.append(finding)
        
        if idx % batch_size == 0 or idx == len(findings):
            batches.append(current_batch)
            current_batch = []
    
    # Send each batch as a separate message
    for batch in batches:
        secret_msg = ""
        for finding in batch:
            detector_name = finding.get("detector_name")
            link = finding.get("link")
            username = finding.get("repo_url").split("/")[-2]
            repo_name = finding.get("repo_url").split("/")[-1]
            branch_name = finding.get("branch")
            commit_hash = finding.get("commit")
            
            secret_msg += f"\n\nRepository Name: {username}/{repo_name}\nDetector: {detector_name}\nLink: {link}"
            
            if branch_name:
                secret_msg += f"\nBranch Name: {branch_name}"
                
            if commit_hash:
                secret_msg += f"\nCommit Hash: {commit_hash}"
        
        log_info(f"Public User Repository Monitoring Detected Secret:\n{secret_msg}", 
                event_type="alert.scan.repo_guardian.secret_found")
        send_notification(webhook, "Public User Repository Monitoring", secret_msg, "#FF0000")
    
    return True

def send_new_repository_alert(webhook, repo_urls):
    """
    Send alert about new repositories to Slack.
    
    Args:
        webhook: Slack webhook client
        repo_urls (list): List of new repository URLs
        
    Returns:
        bool: True if message was sent, False if no new repositories
    """
    if not repo_urls:
        return False
    
    new_repos_msg = "\n".join(repo_urls)
    
    log_info(f"Public User Repository Monitoring - New Repository:\n{new_repos_msg}", 
            event_type="alert.scan.repo_guardian.new_repositories")
    send_notification(webhook, "Public User Repository Monitoring - New Repository", 
                     new_repos_msg, "#FFFF00")
    
    return True
