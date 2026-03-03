import random
import os

ATTACK_BEHAVIORS = ["brute_force", "powershell_exec", "xss_attack", "file_exfiltration"]

COUNTERMEASURES = {
    "brute_force": ["ban_ip", "inject_fake_passwords", "delay_response"],
    "powershell_exec": ["log_ip", "fake_error", "lockout"],
    "xss_attack": ["redirect_to_fake_admin", "ban_ip", "feed_fake_data"],
    "file_exfiltration": ["encrypt_decoy_files", "trace_attacker", "send_ransomware_warning"]
}

def ai_defense(triggered_behavior):
    """AI reacts dynamically based on attacker behavior."""
    response = random.choice(COUNTERMEASURES[triggered_behavior])
    
    if response == "ban_ip":
        os.system("iptables -A INPUT -s ATTACKER_IP -j DROP")
    elif response == "inject_fake_passwords":
        with open("/home/user/Documents/credentials.txt", "w") as f:
            f.write("admin:FakePass123\n")
    elif response == "delay_response":
        os.system("sleep 10")  # Simulate system lag
    elif response == "log_ip":
        with open("/var/log/honeypot_attacks.log", "a") as log:
            log.write(f"⚠️ PowerShell Execution Detected! Logging IP: ATTACKER_IP\n")
    elif response == "fake_error":
        os.system("echo 'System Error: Insufficient Privileges'")
    elif response == "lockout":
        os.system("passwd -l attacker_user")
    elif response == "redirect_to_fake_admin":
        os.system("echo 'Redirecting to admin panel...'")
    elif response == "feed_fake_data":
        os.system("echo 'User credentials leaked: admin:SecurePass!'")
    elif response == "encrypt_decoy_files":
        os.system("gpg --symmetric --passphrase fakepassword /home/user/Documents/HR_Report.docx")
    elif response == "trace_attacker":
        os.system("who -a > /var/log/honeypot_traces.log")
    elif response == "send_ransomware_warning":
        os.system("echo 'Your system is now locked. Contact security@company.com'")
    
    print(f"🛡️ AI Defense Activated: {response}")

# Example: AI detects an XSS Attack and reacts
ai_defense("xss_attack")

