import psutil

# Common EDR processes to detect
EDR_SIGNATURES = ["carbonblack", "crowdstrike", "sentinelone", "mde"]

def detect_security_tools():
    for proc in psutil.process_iter(["pid", "name"]):
        for edr in EDR_SIGNATURES:
            if edr in proc.info["name"].lower():
                return True
    return False

# AI Decides to Evade If EDR Detected
if detect_security_tools():
    print("🔴 Security detected. AI choosing evasion strategy...")
    action = choose_action(4)  # AI picks evasion techniques
else:
    print("🟢 No security detected. AI launching attack...")
    action = choose_action(0)  # AI picks an offensive technique

