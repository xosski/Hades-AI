import os

AUTHORIZED_ENV = ["redteam-lab", "test-server"]
current_env = os.getenv("ENV_NAME", "unauthorized")

if current_env not in AUTHORIZED_ENV:
    print("❌ Unauthorized execution detected. Exiting...")
    exit()

print("✅ Ethical Red Teaming Active")

