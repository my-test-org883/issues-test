import requests
import os

# Replace with your GitLab instance and personal access token
GITLAB_URL = "https://gitlab.com"  # or your self-hosted GitLab instance
# Load token from environment variable instead of hardcoding
TOKEN = os.environ.get("GITLAB_TOKEN")
assert TOKEN, "GITLAB_TOKEN environment variable must be set"


def get_groups():
    url = f"{GITLAB_URL}/api/v4/groups"
    headers = {"PRIVATE-TOKEN": TOKEN}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        groups = response.json()
        for group in groups:
            print(f"- {group['name']} (ID: {group['id']}, Path: {group['path']})")
    else:
        print(f"Error {response.status_code}: {response.text}")


if __name__ == "__main__":
    get_groups()
