import json
import time

AI_TRAINING_LOG = "/var/log/ai_training_data.json"

def log_ai_learning(user_id, action, success, time_taken):
    """Logs user behavior to train AI on deception & evasion techniques."""
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": user_id,
        "action": action,
        "success": success,
        "time_taken": time_taken
    }

    with open(AI_TRAINING_LOG, "a") as log:
        log.write(json.dumps(entry) + "\n")

    print(f"📚 AI Learning Entry: {entry}")

# Example Usage: User took 3 minutes to decrypt a file successfully
log_ai_learning("user123", "decrypted file", True, 180)

