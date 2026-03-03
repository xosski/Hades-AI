ATTACKER_DB = {}

def log_attack(ip, technique):
    """Logs attacker and assigns a risk score."""
    if ip not in ATTACKER_DB:
        ATTACKER_DB[ip] = {"techniques": [], "score": 0}
    
    ATTACKER_DB[ip]["techniques"].append(technique)
    ATTACKER_DB[ip]["score"] += 10  # Increase risk score

    if ATTACKER_DB[ip]["score"] >= 30:
        print(f"⚠️ High-Risk Attacker Detected: {ip} - Deploying Countermeasures!")
        ai_defense(technique)

# Example attack logging
log_attack("192.168.1.100", "file_exfiltration")

