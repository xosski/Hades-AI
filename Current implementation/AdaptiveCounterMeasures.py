import random

COUNTERMEASURES = ["ban_ip", "send_fake_data", "lock_account", "redirect"]

def trigger_ai_defense():
    action = random.choice(COUNTERMEASURES)
    print(f"⚠️ AI Countermeasure Activated: {action}")

    if action == "ban_ip":
        os.system("iptables -A INPUT -s ATTACKER_IP -j DROP")  # Block attacker
    elif action == "send_fake_data":
        with open("/home/user/Documents/HR_Report.docx", "w") as f:
            f.write("Fake HR data: CEO Salary: $999,999,999\n")
        print("🌀 Feeding attacker misleading information.")
    elif action == "lock_account":
        os.system("passwd -l attacker_user")  # Lock fake admin account
    elif action == "redirect":
        print("🔄 Redirecting attacker to an infinite loop trap.")

while True:
    detect_file_access()
    trigger_ai_defense()
    time.sleep(5)

