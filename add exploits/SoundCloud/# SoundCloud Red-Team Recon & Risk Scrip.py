# SoundCloud Red-Team Recon & Risk Script
# Author: GhostCore Recon Ops
# Purpose: Identify exposed user data, DNS behavior, and test hydration vectors

import requests
import json
from urllib.parse import urlparse

# --- Config ---
track_url = "https://soundcloud.com/viperrecordings/blaine-stranger-nev3r-vpr307"
api_url = "https://api-v2.soundcloud.com/resolve?url={}&client_id=2t9loNQH90kzJcsFCODdigxfp325aq4z"
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

# --- Step 1: Resolve Metadata and Hydration Payload ---
print("[*] Resolving track metadata...")
response = requests.get(api_url.format(track_url), headers=headers)
data = response.json()

if 'id' not in data:
    print("[!] Failed to resolve track metadata.")
    exit()

track_id = data['id']
hydrate_url = f"https://api-v2.soundcloud.com/tracks/{track_id}?client_id=2t9loNQH90kzJcsFCODdigxfp325aq4z"
track_details = requests.get(hydrate_url, headers=headers).json()

# --- Step 2: Extract and Display Sensitive Fields ---
def show_key_data(payload):
    print("\n[+] Extracted Metadata:")
    for key in ['permalink_url', 'title', 'user', 'playback_count', 'purchase_url', 'publisher_metadata']:
        print(f"{key}: {payload.get(key)}")

    print("\n[+] GeoIP Data:")
    geo = payload.get('geoip', {})
    print(json.dumps(geo, indent=4))

    print("\n[+] Email Leakage (if present):")
    if 'primary_email' in payload:
        print(f"Email: {payload['primary_email']}")
        print(f"SHA256: {payload.get('primary_email_sha256')}")

show_key_data(track_details)

# --- Step 3: DNS Prefetch Behavior Probe (Manual advisory) ---
dns_targets = ["api-v2.soundcloud.com", "cf.soundcloud.com"]
print("\n[*] Advisory: Test DNS prefetch behavior manually with dig/wireshark or below:")
for domain in dns_targets:
    ip = requests.get(f"https://dns.google/resolve?name={domain}").json()
    answer = ip.get("Answer", [{}])[0].get("data", "N/A")
    print(f"Resolved {domain} to {answer}")

# --- Step 4: Permalink Injection Test Stub ---
print("\n[*] Injection Probe Suggestion:")
permalink = track_details.get("permalink", "")
print(f"Example payload vector: https://soundcloud.com/viperrecordings/<script>alert('xss')</script>")
