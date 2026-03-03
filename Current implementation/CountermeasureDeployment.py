import time
import psutil

def detect_anomalies():
    cpu_usage = psutil.cpu_percent()
    mem_usage = psutil.virtual_memory().percent

    if cpu_usage > 80 or mem_usage > 75:
        print("⚠️ Anomaly detected! Deploying AI Countermeasure...")
        deploy_ai_defense()

def deploy_ai_defense():
    action = choose_defense(4)  # Pick AI countermeasure
    print(f"🛡️ AI Deploying: {action}")

while True:
    detect_anomalies()
    time.sleep(3)

