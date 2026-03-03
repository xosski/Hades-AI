import psutil

def detect_anomaly():
    cpu_usage = psutil.cpu_percent()
    mem_usage = psutil.virtual_memory().percent

    if cpu_usage > 80 or mem_usage > 75:
        print("⚠️ Anomalous AI behavior detected!")
        deploy_countermeasure()

def deploy_countermeasure():
    print("🛑 Deploying automated defense: Memory restriction")
    # Implement security controls dynamically

while True:
    detect_anomaly()

