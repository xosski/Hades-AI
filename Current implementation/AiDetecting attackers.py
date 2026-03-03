import os
import time

ACTIVE_ATTACKERS = {}

def detect_active_sessions():
    """Detects attackers currently connected via SSH or interactive shells."""
    global ACTIVE_ATTACKERS
    active_ips = os.popen("who | awk '{print $5}'").read().split("\n")
    
    for ip in active_ips:
        if ip and ip not in ACTIVE_ATTACKERS:
            ACTIVE_ATTACKERS[ip] = time.time()  # Log attacker entry time
            print(f"⚠️ New attacker detected: {ip}")

def attacker_recently_active(ip):
    """Checks if an attacker was recently connected within the last 3 hours."""
    if ip in ACTIVE_ATTACKERS and (time.time() - ACTIVE_ATTACKERS[ip] < 10800):  # 3 hours
        return True
    return False

while True:
    detect_active_sessions()
    time.sleep(10)

