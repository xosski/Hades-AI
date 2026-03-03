import time
import random

ATTACKER_BEHAVIOR = {}

def detect_ai_behavior(ip):
    """Detects AI vs. human behavior based on interaction patterns."""
    global ATTACKER_BEHAVIOR

    now = time.time()
    if ip not in ATTACKER_BEHAVIOR:
        ATTACKER_BEHAVIOR[ip] = []

    ATTACKER_BEHAVIOR[ip].append(now)

    # Check frequency of interactions
    if len(ATTACKER_BEHAVIOR[ip]) > 5:
        time_diffs = [ATTACKER_BEHAVIOR[ip][i+1] - ATTACKER_BEHAVIOR[ip][i] for i in range(len(ATTACKER_BEHAVIOR[ip]) - 1)]
        avg_time = sum(time_diffs) / len(time_diffs)

        if avg_time < 1:  # If the attacker interacts too fast, it's likely a bot
            print(f"🤖 AI Bot Detected: {ip} - Deploying Infinite Loop Trap!")
            deploy_ai_trap(ip)

def deploy_ai_trap(ip):
    """Redirects AI-driven attacks into an infinite deception loop."""
    print(f"🔄 AI attacker {ip} trapped in a deception loop.")

    # Fake large dataset for AI to process
    with open(f"/home/user/Documents/fake_data_{ip}.csv", "w") as f:
        for _ in range(1000000):
            f.write(f"user{random.randint(1, 99999)},password{random.randint(1, 99999)},email{random.randint(1, 99999)}@fake.com\n")

detect_ai_behavior("192.168.1.100")

