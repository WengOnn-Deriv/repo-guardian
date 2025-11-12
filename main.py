import requests
import json
from dotenv import load_dotenv
import yaml 
import pathlib
import os
from datetime import datetime, timedelta
import subprocess
import logging
import time
import shutil
from slack_sdk.webhook import WebhookClient

ROOT_PATH = str(pathlib.Path(__file__).parent.resolve())

load_dotenv(f"{ROOT_PATH}/configs/.env", override=True)

with open(f"{ROOT_PATH}/configs/config.yaml", "r") as configs:
    ORGS = yaml.safe_load(configs)["organizations"]
    
TOKEN = os.getenv("GITHUB_TOKEN")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")

# GraphQL endpoint
GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

def run_graphql_query(query, variables=None):
    """
    Execute a GraphQL query against GitHub's API with exponential backoff
    """
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
    }
    
    payload = {
        "query": query,
        "variables": variables or {}
    }
    
    # Retry delays: 1 min, 3 min, 5 min (in seconds)
    delays = [60, 180, 300]
    
    for attempt in range(4):  # 0, 1, 2, 3 (initial + 3 retries)
        response = requests.post(GITHUB_GRAPHQL_URL, headers=headers, json=payload)
        
        if response.status_code == 200:
            return response.json()
        
        # Log the failure
        logging.info(f"Error: {response.status_code} (attempt {attempt + 1})")
        logging.info(response.text)
        
        # If this was the last attempt, return None
        if attempt == 3:
            return None
        
        # Wait before retrying
        delay = delays[attempt]
        logging.info(f"Waiting {delay} seconds before retry...")
        time.sleep(delay)
    
    return None

def get_org_members(org):
    """
    Fetch all members from github organizations using GraphQL
    """
    logging.info(org)
    
    members = []
    has_next_page = True
    cursor = None
    
    # GraphQL query for organization members with pagination
    query = """
    query($org: String!, $cursor: String) {
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
        
        result = run_graphql_query(query, variables)
        
        if not result:
            logging.info(f"Error fetching members for {org}: GraphQL query failed")
            return None
        
        if "errors" in result:
            logging.info(f"Error fetching members for {org}:")
            logging.info(result["errors"])
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

def get_user_repos(member):
    """
    Fetch org members public repositories using GraphQL
    """
    repos = []
    has_next_page = True
    cursor = None
    
    logging.info(f"Getting repos for {member}...")
    
    # GraphQL query for user repositories with pagination
    query = """
    query($username: String!, $cursor: String) {
      user(login: $username) {
        repositories(first: 100, after: $cursor, privacy: PUBLIC) {
          pageInfo {
            hasNextPage
            endCursor
          }
          nodes {
            url
          }
        }
      }
    }
    """
    
    while has_next_page:
        variables = {
            "username": member,
            "cursor": cursor
        }
        
        result = run_graphql_query(query, variables)
        
        if not result:
            logging.info(f"Error fetching repos for {member}: GraphQL query failed")
            return None
        
        if "errors" in result:
            logging.info(f"Error fetching repos for {member}:")
            logging.info(result["errors"])
            return None
        
        data = result.get("data", {})
        user_data = data.get("user", {})
        repos_data = user_data.get("repositories", {})
        
        # Extract repository URLs
        for repo in repos_data.get("nodes", []):
            repos.append(repo["url"])
        
        # Check if there are more pages
        page_info = repos_data.get("pageInfo", {})
        has_next_page = page_info.get("hasNextPage", False)
        cursor = page_info.get("endCursor", None)
    
    return repos

def setup_logging(log_file):
    formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

def trufflehog_scan(repo_url):
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
    
    if jq_process.returncode != 0:
        logging.info(f"jq command failed: {error}")
        return [], []
        
    if trufflehog_process.returncode != 0:
        logging.info(f"TruffleHog scan failed for {repo_url}")
        return [], []
    
    try:
        findings = []
        results = json.loads(output)
        logging.info(f"TruffleHog scan completed for {repo_url}. Found {len(results)} results.")  

        for result in results:
            detector_name = result.get("DetectorName")
            link = result["SourceMetadata"]["Data"]["Github"]["link"]
            finding = {
                "detector_name": detector_name,
                "link": link,
                "repo_url": repo_url
            }
            findings.append(finding)


        return findings, results
    except json.JSONDecodeError as e:
        logging.info(f"Failed to parse JSON output: {e}")
        return [], []
    
def slack_notification(webhook, title, msg, color):    

    logging.info("Sending slack message...")

    response = webhook.send(
            text= title, 
            attachments=[
                {
                    "color": color,
                    "fields": [{"value": msg}], 
                }
            ]
        )
    

def cleanup_incomplete_scan(scan_dir):
    """
    Remove incomplete scan directory and log the cleanup
    """
    try:
        if os.path.exists(scan_dir):
            shutil.rmtree(scan_dir)
            logging.info(f"Removed incomplete scan directory: {scan_dir}")
            return True
    except Exception as e:
        logging.info(f"Failed to cleanup scan directory {scan_dir}: {e}")
        return False
    return False

def main():
    slack_webhook = WebhookClient(SLACK_WEBHOOK)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")

    log_dir = os.path.join(ROOT_PATH, "logs")
    os.makedirs(log_dir, exist_ok=True)

    setup_logging(f"{log_dir}/{timestamp}.log")
 
    try:
        # This will be previous scan result folder name    
        previous_scan = sorted(os.listdir(f"{ROOT_PATH}/scan_results"), reverse=True)

        if previous_scan:
            logging.info(f"previous_scan: {previous_scan[0]}")
            with open(f"{ROOT_PATH}/scan_results/{previous_scan[0]}/repos.txt", 'r') as file:
                previous_scan_repositories = [line.strip() for line in file]
        else:
            previous_scan_repositories = []
    except:
        previous_scan_repositories = []


    scan_dir = os.path.join(ROOT_PATH, "scan_results", timestamp)
    os.makedirs(scan_dir, exist_ok=True)
    
    scan_failed = False
    members = []

    # Track failures during member collection
    for org in ORGS:
        org_members = get_org_members(org)
        if org_members is None:  # get_org_members failed
            logging.info(f"Failed to get members for organization: {org}")
            scan_failed = True
            break
        members.extend(org_members)

    if not scan_failed:
        members = list(set(members))
        repos = []
        
        # Track failures during repository collection
        for member in members:
            member_repos = get_user_repos(member)
            if member_repos is None:  # get_user_repos failed
                logging.info(f"Failed to get repositories for member: {member}")
                scan_failed = True
                break
            repos.extend(member_repos)

    # Cleanup if scan failed
    if scan_failed:
        cleanup_incomplete_scan(scan_dir)
        logging.info("Scan failed due to GraphQL errors. Incomplete results cleaned up.")
        return  # Exit early

    with open(f"{scan_dir}/repos.txt", "w") as f:
        f.write("\n".join(repos))

    new_repos = []
    for repo in repos:
        if repo not in previous_scan_repositories:
            new_repos.append(repo)
    
    with open(f"{scan_dir}/new_repos.txt", "w") as f:
        f.write("\n".join(new_repos))
    
    all_findings = []
    all_raw_output = []
    if new_repos:
        msg = '\n'.join(new_repos)
        slack_notification(slack_webhook, "New Public User Repository", msg, "#FFFF00")

        for repo in new_repos:
            logging.info(f"Performing trufflehog scan for: {repo}")
            trufflehog_findings, raw_output = trufflehog_scan(repo_url=repo)
            all_findings.extend(trufflehog_findings)
            all_raw_output.extend(raw_output)
    else:
        # slack_notification(slack_webhook, "New Public User Repository", "No new repositories found", "#008000")
        logging.info(f"No new repositories found, skipping trufflehog scan")

    with open(f"{scan_dir}/raw_output.json", "a") as f:
        json.dump(all_raw_output, f, indent=4)

    secret_msg = ""
    for idx, finding  in enumerate(all_findings, start=1):
        detector_name = finding.get("detector_name")
        link = finding.get("link")
        username = finding.get("repo_url").split("/")[-2]
        repo_name = finding.get("repo_url").split("/")[-1]
        secret_msg = secret_msg + f"Repository Name: {username}/{repo_name}\nDetector: {detector_name}\nLink: {link}" + "\n\n"

        # Break into multiple slack messages to prevent the slack message from being truncated
        if idx % 5 == 0 or idx == len(all_findings):
            slack_notification(slack_webhook, "New Public User Repository Secret Scan", secret_msg, "#FF0000")
            secret_msg = ""

    if not all_findings:
        logging.info("trufflehog scan - no secret found")
        # slack_notification(slack_webhook, "New Public User Repository Secret Scan", "No Secret Found", "#008000")
           

if __name__ == "__main__":
    main()
