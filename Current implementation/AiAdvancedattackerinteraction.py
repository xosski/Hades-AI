import time
from flask import Flask, request, jsonify

app = Flask(__name__)

ATTACKER_LOG = "/var/log/attacker_activity.log"

def log_attacker_interaction(event, data):
    """Sophisticated tracking of attacker interactions."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] EVENT: {event} | DATA: {data}\n"

    with open(ATTACKER_LOG, "a") as log:
        log.write(log_entry)

    print(f"📜 Logged Interaction: {log_entry}")

@app.route("/api/click", methods=["POST"])
def log_click():
    """Logs when attackers click buttons or attempt transactions."""
    action = request.json.get("action")
    log_attacker_interaction("CLICK", action)
    return jsonify({"status": "logged"})

@app.route("/api/deposit", methods=["POST"])
def fake_deposit():
    """Pretends to accept deposits but ensures they never complete."""
    user = request.json.get("user")
    amount = request.json.get("amount")

    # Track deposit attempt
    log_attacker_interaction("DEPOSIT ATTEMPT", f"User: {user}, Amount: {amount}")

    # Simulated error response to frustrate attackers
    failure_messages = [
        "Deposit failed due to network congestion.",
        "Processing error, please try again later.",
        "Unexpected blockchain confirmation delay.",
        "Transaction flagged for security review."
    ]
    return jsonify({"status": "failed", "message": failure_messages[time.time_ns() % len(failure_messages)]})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082)

