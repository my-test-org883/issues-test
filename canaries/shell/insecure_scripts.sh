#!/bin/bash

# Shell script vulnerabilities for testing

# Vulnerability #1: Command injection via user input
echo "Enter filename to process:"
read filename
# Vulnerable: Direct execution without validation
cat $filename | grep "pattern"

# Vulnerability #2: Unquoted variables
user_input="$1"
# Vulnerable: Unquoted variable can cause word splitting
rm $user_input

# Vulnerability #3: Using eval with user input
command_to_run="$2"
# Vulnerable: eval executes arbitrary code
eval $command_to_run

# Vulnerability #4: Hardcoded credentials
DB_PASSWORD="admin123"
mysql -u admin -p$DB_PASSWORD -e "SELECT * FROM users;"

# Vulnerability #5: Insecure temp file creation
temp_file="/tmp/data_$$"
# Vulnerable: Predictable temp file names
echo "sensitive data" > $temp_file
chmod 777 $temp_file

# Vulnerability #6: Command substitution without validation
url="$3"
# Vulnerable: Arbitrary command execution
result=$(curl -s $url)
echo $result

# Vulnerability #7: Unsafe find with exec
search_dir="$4"
# Vulnerable: Arbitrary command execution
find $search_dir -name "*.txt" -exec rm {} \;

# Vulnerability #8: Using deprecated backticks
server=`hostname`
# Vulnerable: Command substitution with backticks
ping -c 1 $server

# Vulnerability #9: Insecure file permissions
config_file="/etc/myapp.conf"
echo "secret_key=12345" > $config_file
chmod 644 $config_file  # Readable by all users

# Vulnerability #10: Race condition in file operations
if [ ! -f "/tmp/lockfile" ]; then
    # Vulnerable: Race condition between check and use
    echo "Process started" > /tmp/lockfile
    # ... do work ...
    rm /tmp/lockfile
fi