#!/bin/bash

# Insecure deployment script with multiple vulnerabilities

# Vulnerability #1: Hardcoded AWS credentials
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Vulnerability #2: No input validation
APP_NAME="$1"
VERSION="$2"
ENVIRONMENT="$3"

# Vulnerability #3: Command injection via unquoted variables
echo "Deploying $APP_NAME version $VERSION to $ENVIRONMENT"
docker build -t $APP_NAME:$VERSION .

# Vulnerability #4: Downloading and executing scripts from internet
curl -s https://get.docker.com | bash

# Vulnerability #5: Using sudo without password (assuming NOPASSWD sudoers)
sudo docker run -d --name $APP_NAME \
  --privileged \
  -v /:/host \
  -p 80:8080 \
  $APP_NAME:$VERSION

# Vulnerability #6: Insecure secret handling
DB_PASSWORD=$(cat /tmp/db_password.txt)
echo "Database password: $DB_PASSWORD"  # Vulnerable: logging secrets

# Vulnerability #7: Weak file permissions for sensitive files
echo "$DB_PASSWORD" > /tmp/app_secrets.txt
chmod 644 /tmp/app_secrets.txt

# Vulnerability #8: Command substitution without proper escaping
server_list=`aws ec2 describe-instances --query 'Reservations[].Instances[].PublicDnsName' --output text`
for server in $server_list; do
    # Vulnerable: SSH without host key verification
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@$server "docker pull $APP_NAME:$VERSION"
done

# Vulnerability #9: Using curl without certificate verification
API_TOKEN="sk-1234567890abcdefghijklmnopqrstuvwx"
curl -k -H "Authorization: Bearer $API_TOKEN" \
     https://api.internal.com/deploy \
     -d "{\"app\":\"$APP_NAME\",\"version\":\"$VERSION\"}"

# Vulnerability #10: Cleanup that could be dangerous
cleanup() {
    # Vulnerable: Potential for directory traversal
    rm -rf /tmp/$APP_NAME/*
    # Vulnerable: Overly broad cleanup
    docker system prune -af
}

trap cleanup EXIT