import random
import os

COUNTERMEASURES = {
    "low": ["inject_fake_credentials", "delay_response", "fake_error"],
    "medium": ["trace_attacker", "lock_account", "reroute_to_fake_admin"],
    "high": ["wipe_fake_files", "isolate_network", "lock_tty", "force_reboot"]
}

def aggressive_defense(severity):
    """Selects an aggressive defense action based on attack level."""
    action = random.choice(COUNTERMEASURES[severity])

    if action == "inject_fake_credentials":
        with open("/home/user/Documents/passwords.txt", "w") as f:
            f.write("admin:WrongPass123\nroot:FakeSecurePass!")
    elif action == "delay_response":
        os.system("sleep 5")
    elif action == "fake_error":
        os.system("echo 'System Error: Kernel Panic' > /tmp/system_error.log")
    elif action == "trace_attacker":
        os.system("who -a > /var/log/honeypot_traces.log")
    elif action == "lock_account":
        os.system("passwd -l attacker_user")
    elif action == "reroute_to_fake_admin":
        os.system("echo 'Redirecting attacker to false security console...'")
    elif action == "wipe_fake_files":
        os.system("rm -rf /home/user/Documents/*")  # Deletes ONLY fake decoy files
    elif action == "isolate_network":
        os.system("iptables -A INPUT -s ATTACKER_IP -j DROP")
    elif action == "lock_tty":
        os.system("chage -E 0 attacker_user")  # Immediately locks the shell
    elif action == "force_reboot":
        os.system("shutdown -r now")

    print(f"🛡️ AI Countermeasure Deployed: {action}")

# Example: If attacker escalates, use "high" severity
aggressive_defense("high")