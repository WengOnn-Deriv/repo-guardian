# Repo Guardian

A Python-based security scanner that monitors GitHub organizations for new public repositories and automatically scans them for exposed secrets using TruffleHog. The tool provides Slack notifications for new repositories and any security findings.

## Features

- **Organization Monitoring**: Scans multiple GitHub organizations for all public repositories
- **Incremental Scanning**: Only scans new repositories since the last run, improving efficiency
- **Secret Detection**: Uses TruffleHog to scan for exposed secrets, API keys, and credentials
- **Slack Integration**: Sends notifications for new repositories and security findings
- **Comprehensive Logging**: Detailed logging to both console and files
- **Structured Output**: Organized scan results with timestamps and raw data preservation

## Prerequisites

Before running the scanner, ensure you have the following installed:

- **Python 3.7+**
- **TruffleHog**: Secret scanning tool
  ```bash
  # Install via pip
  pip install trufflehog
  
  # Or via Go
  go install github.com/trufflesecurity/trufflehog/v3@latest
  ```
- **jq**: JSON processor
  ```bash
  # Ubuntu/Debian
  sudo apt-get install jq
  
  # macOS
  brew install jq
  ```

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd scan_user_repo
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up configuration files** (see Configuration section below)

## Configuration

### Environment Variables

Create a `.env` file in the `configs/` directory with the following variables:

```bash
# configs/.env
GITHUB_TOKEN=your_github_personal_access_token
SLACK_WEBHOOK=your_slack_webhook_url
```

**GitHub Token Requirements:**
- Personal Access Token with the following scopes:
  - `read:org` - Read organization membership
  - `public_repo` - Access public repositories
  - `read:user` - Read user profile information

### Organization Configuration

Edit `configs/config.yaml` to specify the GitHub organizations to monitor:

```yaml
organizations:
  - your-org-1
  - your-org-2
  - your-org-3
```

### Slack Webhook Setup

1. Create a Slack app in your workspace
2. Enable Incoming Webhooks
3. Create a webhook URL for your desired channel
4. Add the webhook URL to your `.env` file

## Usage

Run the scanner with:

```bash
python main.py
```

The scanner will:
1. Fetch all members from configured organizations
2. Retrieve public repositories for each member
3. Compare against previous scans to identify new repositories
4. Scan new repositories with TruffleHog for secrets
5. Send Slack notifications with results
6. Save all results to timestamped directories

## Output Structure

The scanner creates the following directory structure:

```
scan_results/
├── 2025-01-15_14:30:25/
│   ├── repos.txt          # All repositories found
│   ├── new_repos.txt      # New repositories since last scan
│   └── raw_output.json    # Raw TruffleHog scan results
├── 2025-01-15_10:15:42/
│   └── ...
└── ...

logs/
├── 2025-01-15_14:30:25.log
└── ...
```

### File Descriptions

- **`repos.txt`**: Complete list of all public repositories found across all organization members
- **`new_repos.txt`**: Repositories that weren't present in the previous scan
- **`raw_output.json`**: Complete TruffleHog scan results in JSON format
- **Log files**: Detailed execution logs with timestamps

## Slack Notifications

The scanner sends three types of Slack notifications:

1. **New Repositories Found** (Yellow):
   - Lists all newly discovered public repositories
   - Sent when new repositories are detected

2. **No New Repositories** (Green):
   - Confirmation message when no new repositories are found

3. **Secret Scan Results** (Red):
   - Details of any secrets found by TruffleHog
   - Includes repository name, detector type, and direct link to the finding
   - Messages are batched (5 findings per message) to prevent truncation

## Security Considerations

- **Token Security**: Store your GitHub token securely and never commit it to version control
- **Webhook Security**: Protect your Slack webhook URL as it provides direct access to your channel
- **Permissions**: The scanner only accesses public repositories and organization membership information
- **Data Retention**: Consider implementing a retention policy for scan results and logs

## Troubleshooting

### Common Issues

**1. "Authentication failed" errors**
- Verify your GitHub token is valid and has the required scopes
- Check that the token hasn't expired

**2. "Organization not found" errors**
- Ensure organization names in `config.yaml` are correct
- Verify your token has access to read the organization's membership

**3. TruffleHog command not found**
- Install TruffleHog using the instructions in Prerequisites
- Ensure TruffleHog is in your system PATH

**4. jq command not found**
- Install jq using the instructions in Prerequisites

**5. Slack notifications not working**
- Verify your webhook URL is correct
- Check that the Slack app has permission to post to the channel

### Debug Mode

For detailed debugging, check the log files in the `logs/` directory. Each run creates a timestamped log file with comprehensive execution details.

## Development

### Code Structure

- **`main.py`**: Main application logic
- **`configs/`**: Configuration files
- **`scan_results/`**: Output directory for scan results
- **`logs/`**: Application logs

### Key Functions

- **`get_org_members(org)`**: Fetches organization members using GraphQL
- **`get_user_repos(member)`**: Retrieves user's public repositories
- **`trufflehog_scan(repo_url)`**: Performs secret scanning on a repository
- **`slack_notification(webhook, title, msg, color)`**: Sends Slack messages

### Dependencies

- `requests`: HTTP client for GitHub API calls
- `python-dotenv`: Environment variable management
- `PyYAML`: YAML configuration file parsing
- `slack_sdk`: Slack webhook integration

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review the log files for detailed error information
3. Open an issue in the repository with relevant log excerpts
