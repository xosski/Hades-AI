import os
import random
import time
import base64

FAKE_SECRET = "TOP_SECRET_ACCESS_KEY=abcd-1234-efgh-5678"

DOWNLOAD_FOLDER = "/home/user/Downloads/"
ENCRYPTED_FILE = os.path.join(DOWNLOAD_FOLDER, "decrypted_secrets.enc")

# Simulate creating an "encrypted" file
with open(ENCRYPTED_FILE, "w") as f:
    encoded_secret = base64.b64encode(FAKE_SECRET.encode()).decode()
    f.write(f"ENCRYPTED DATA: {encoded_secret}\n")

print(f"💾 Fake encrypted file created: {ENCRYPTED_FILE}")

def detect_decryption():
    """Detects when an attacker tries to decrypt the fake file."""
    while True:
        if os.path.exists(ENCRYPTED_FILE) and os.stat(ENCRYPTED_FILE).st_atime > time.time() - 60:
            print("⚠️ Attacker attempting decryption!")
            deploy_deception()
        time.sleep(5)

def deploy_deception():
    """Pretends to decrypt while leading attacker further into the trap."""
    decrypted_file = os.path.join(DOWNLOAD_FOLDER, "decrypted_secrets.txt")
    
    with open(decrypted_file, "w") as f:
        fake_content = f"""
        AWS_ACCESS_KEY=EXPIRED
        SSH_PRIVATE_KEY=FAKE_RSA_KEY
        VPN_CREDENTIALS=DECOY_VPN_SECRET
        """
        f.write(fake_content)

    print(f"🔓 Fake decryption complete: {decrypted_file}")
    os.system(f"chmod 444 {decrypted_file}")  # Make it read-only to look authentic

detect_decryption()

