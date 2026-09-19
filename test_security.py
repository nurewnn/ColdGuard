import requests
import json
from security import load_secret, generate_signature

try:
    with open('config.json', 'r') as f:
        config = json.load(f)
except FileNotFoundError:
    print("CRITICAL: config.json not found! Copy config.example.json to config.json.")
    exit(1)

SERVER_URL = config.get('server_url')
SECRET_KEY = load_secret()

valid_event = {
    "device_id": config.get('device_id'),
    "event_id": "demo-attack-001",
    "sequence": 999999,
    "timestamp": "2026-09-19T14:00:00Z",
    "event_type": "temperature",
    "simulated": True,
    "data": {"temperature_c": 5.0}
}

payload_str = json.dumps(valid_event, separators=(',', ':'), sort_keys=True)
valid_signature = generate_signature(SECRET_KEY, payload_str.encode('utf-8'))

print("--- RUNNING CONTROLLED STAGE 2 ATTACKS ---")

altered_payload = payload_str.replace("5.0", "20.0")
print("\n1. Sending Altered Message (Should fail BAD_AUTHENTICATION)...")
r1 = requests.post(SERVER_URL, data=altered_payload, headers={'Content-Type': 'application/json', 'X-Signature': valid_signature})
print(f"Result: {r1.status_code} - {r1.text}")

print("\n2. Sending Valid Message (Should pass)...")
r2 = requests.post(SERVER_URL, data=payload_str, headers={'Content-Type': 'application/json', 'X-Signature': valid_signature})
print(f"Result: {r2.status_code} - {r2.text}")

print("\n3. Sending Replay Attack (Should fail REPLAY)...")
r3 = requests.post(SERVER_URL, data=payload_str, headers={'Content-Type': 'application/json', 'X-Signature': valid_signature})
print(f"Result: {r3.status_code} - {r3.text}")
