# Repo Guardian

A security tool that monitors GitHub repositories of organization members for changes and scans for potential secrets using TruffleHog.

## Overview

Repo Guardian continuously monitors GitHub repositories belonging to members of specified organizations. It detects:

- New repositories
- New branches
- Updated commits

When changes are detected, it automatically scans them using TruffleHog to identify potential secrets or sensitive information that may have been accidentally committed. Findings can be sent to Slack for immediate notification.

## Prerequisites

- Python 3.6+
- GitHub Personal Access Token with appropriate permissions
- Slack Webhook URL (for notifications)
- TruffleHog CLI installed and available in PATH
  - Download from: https://github.com/trufflesecurity/trufflehog
- jq command-line JSON processor
  - Install with: `apt-get install jq` (Ubuntu/Debian)
  - Or: `brew install jq` (macOS)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/your-org/repo-guardian.git
   cd repo-guardian
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure the application:
   - Create a `.env` file in the `configs` directory with:
     ```
     GITHUB_TOKEN=your_github_token
     SLACK_WEBHOOK=your_slack_webhook_url
     ```
   - Update `configs/config.yaml` with your organization names:
     ```yaml
     organizations:
       - your-organization-1
       - your-organization-2
     ```

## Usage

### Basic Usage

Run the scanner with:

```
python main.py
```

This will:
1. Fetch all members from the specified organizations
2. Retrieve their repositories and branch information
3. Compare with previous scan results to identify changes
4. Scan changes with TruffleHog
5. Send notifications for any findings

### Options

- `--no-trufflehog`: Skip the TruffleHog scanning step (Useful for first scan)
  ```
  python main.py --no-trufflehog
  ```

## Continuous Monitoring

For effective security monitoring, it's recommended to run Repo Guardian regularly. You can set it up as:

### Cron Job (Linux/macOS)

Add a cron job to run the script at regular intervals:

```bash
# Edit crontab
crontab -e

# Add a line to run every 6 hours (adjust path as needed)
0 */6 * * * cd /path/to/repo-guardian && python main.py >> /path/to/repo-guardian/cron.log 2>&1
```

### Task Scheduler (Windows)

1. Open Task Scheduler
2. Create a new Basic Task
3. Set the trigger (e.g., Daily)
4. Set the action to start a program:
   - Program/script: `python`
   - Arguments: `main.py`
   - Start in: `C:\path\to\repo-guardian`

## How It Works

1. **Organization Member Discovery**: Fetches all members from the configured GitHub organizations
2. **Repository Monitoring**: Uses GitHub's GraphQL API to efficiently retrieve repository and branch information
3. **Change Detection**: Compares current scan with previous scan to identify new or updated content
4. **Secret Scanning**: Uses TruffleHog to scan changes for potential secrets
5. **Notification**: Sends findings to Slack for immediate action

## Output

Scan results are stored in the `scan_results` directory, organized by timestamp:
- `commit_hash.json`: Current state of all repositories
- `updated_commit.json`: Commits that have been updated since last scan
- `new_repo.json`: New repositories detected
- `new_branch.json`: New branches detected
- `trufflehog_scan_results/`: TruffleHog scan findings

## Logging

The application uses a standard Python logger with rotation support. Logs are stored in `repo_guardian_scanner.log` with the following information:
- Timestamp
- Log level
- Service name
- Message
- Event type
