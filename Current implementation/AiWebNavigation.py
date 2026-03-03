import webbrowser
import time
import random
import os

# High-risk sites for potential XSS exposure
SITES = [
    "https://www.pornhub.com",
    "https://www.nudevista.com",
    "https://www.motherless.com",
    "https://www.4chan.org/b/",
    "https://darkwebmarketplace.com",
    "https://www.freenulledscripts.com",
    "https://randomwarezsite.com"
]

# Fake download types to simulate
FAKE_FILES = [
    ("cracked_software.zip", "Executable exploit"),
    ("nulled_plugin.rar", "Compromised WordPress plugin"),
    ("leaked_database.sql", "Stolen credentials"),
    ("hacked_account_list.txt", "Account dump"),
    ("vpn_premium_crack.exe", "Fake VPN crack"),
    ("browser_exploit.js", "Malicious JavaScript file")
]

DOWNLOAD_FOLDER = "/home/user/Downloads/"

def browse_and_download():
    """AI simulates browsing and fake downloading files."""
    while True:
        site = random.choice(SITES)
        print(f"🌐 Visiting: {site}")
        webbrowser.open(site)
        
        time.sleep(random.randint(5, 15))  # Simulate browsing

        # Simulate a "download" happening
        file_name, description = random.choice(FAKE_FILES)
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        saved_file = os.path.join(DOWNLOAD_FOLDER, f"{timestamp}_{file_name}")

        with open(saved_file, "w") as fake_file:
            fake_file.write(f"Fake {description} - Generated on {timestamp}\n")

        print(f"💾 Download initiated: {saved_file}")

        time.sleep(random.randint(30, 300))  # Wait before next action

browse_and_download()


import os
import time

MONITORED_FOLDER = "/home/user/Downloads/"
LOG_FILE = "/var/log/honeypot_access.log"

def detect_file_access():
    """Detects when an attacker opens a fake downloaded file."""
    for file in os.listdir(MONITORED_FOLDER):
        file_path = os.path.join(MONITORED_FOLDER, file)
        if os.path.isfile(file_path):
            access_time = os.stat(file_path).st_atime  # Last access time
            now = time.time()

            if now - access_time < 60:  # File accessed within the last minute
                log_access(file_path)
                trigger_shadow_trap(file_path)

def log_access(file):
    """Logs access to the fake downloads."""
    with open(LOG_FILE, "a") as log:
        log.write(f"⚠️ Fake Download Accessed: {file} at {time.ctime()}\n")

def trigger_shadow_trap(file):
    """Deploys deception-based AI countermeasures."""
    print(f"🛑 ALERT: Attacker accessed fake file - {file}")

    # Example countermeasures
    os.system("iptables -A OUTPUT -p tcp --dport 443 -j DROP")  # Block outgoing traffic
    os.system("echo 'System Error: Corrupt File Detected' > /tmp/system_error.log")  # Fake system corruption message

while True:
    detect_file_access()
    time.sleep(5)


