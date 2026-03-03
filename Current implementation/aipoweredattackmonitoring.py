import os
import time

MONITORED_FILES = [
    "/home/user/Desktop/bank_accounts.txt",
    "/home/user/Documents/encryption_keys.key",
    "/home/user/Downloads/hr_salaries.xlsx"
]

def detect_access():
    for file in MONITORED_FILES:
        if os.path.exists(file) and os.stat(file).st_atime > time.time() - 60:
            print(f"⚠️ File Access Detected: {file}")
            trigger_containment()

def trigger_containment():
    print("🛑 AI Kill Switch Activated - Containing Attacker")
    os.system("shutdown -h now")  # Or disconnect from network

while True:
    detect_access()
    time.sleep(5)

