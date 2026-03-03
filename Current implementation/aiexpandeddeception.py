import os
import time

MONITORED_FILES = ["/home/user/Documents/HR_Report.docx", "/home/user/Documents/Security_Credentials.txt"]
LOG_FILE = "/var/log/honeypot.log"

def detect_file_access():
    for file in MONITORED_FILES:
        if os.path.exists(file) and os.stat(file).st_atime > time.time() - 60:
            with open(LOG_FILE, "a") as log:
                log.write(f"⚠️ Unauthorized Access: {file} - {time.ctime()}\n")
            trigger_response(file)

def trigger_response(file):
    print(f"🛑 ALERT: Suspicious Activity Detected on {file}")
    os.system("iptables -A OUTPUT -p tcp --dport 80 -j DROP")  # Block attacker’s outbound connections

while True:
    detect_file_access()
    time.sleep(5)

import os
import time
import subprocess

# Define decoy files to monitor
MONITORED_FILES = [
    "/home/user/Documents/HR_Report.docx",
    "/home/user/Documents/Security_Credentials.txt",
    "/home/user/Downloads/Financial_Records.xlsx"
]

LOG_FILE = "/var/log/honeypot_access.log"

def detect_file_access():
    for file in MONITORED_FILES:
        if os.path.exists(file):
            # Check access times
            atime = os.stat(file).st_atime  # Last access time
            mtime = os.stat(file).st_mtime  # Last modification time
            now = time.time()

            if (now - atime < 60) or (now - mtime < 60):  # If accessed within the last minute
                log_access(file)
                trigger_response(file)

def log_access(file):
    """Logs the access to honeypot log file."""
    with open(LOG_FILE, "a") as log:
        log.write(f"⚠️ File Access Detected: {file} at {time.ctime()}\n")

def trigger_response(file):
    """AI-based countermeasure activation"""
    print(f"🛑 ALERT: Unauthorized Access on {file}")

    # AI Countermeasures based on access frequency
    access_count = count_access_attempts(file)

    if access_count == 1:
        print("🔍 First access detected. Monitoring...")
    elif access_count == 3:
        print("🚨 Multiple access attempts! Deploying firewall rule...")
        subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "DROP"])
    elif access_count >= 5:
        print("🛑 Kill switch activated! Locking attacker out.")
        os.system("passwd -l attacker_user")  # Lock the attacker’s session

def count_access_attempts(file):
    """Count how many times a file has been accessed from the logs."""
    count = 0
    with open(LOG_FILE, "r") as log:
        for line in log:
            if file in line:
                count += 1
    return count

while True:
    detect_file_access()
    time.sleep(5)  # Check every 5 seconds

