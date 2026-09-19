import requests
import json
import datetime
import os

import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.security import load_secret, generate_signature

CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config.json')
try:
    with open(CONFIG_PATH, 'r') as f:
        config = json.load(f)
except FileNotFoundError:
    print("CRITICAL: config.json not found! Copy config.example.json to config.json.")
    exit(1)

SERVER_URL = config.get('server_url')
SECRET_KEY = load_secret('~/.config/coldguard/device.key')

LOG_DIR = os.path.expanduser(config.get('log_dir', '~/.local/state/coldguard'))
SEQ_FILE = os.path.join(LOG_DIR, "pi_sequence.txt")
os.makedirs(LOG_DIR, exist_ok=True)

def get_next_sequence():
    seq = 0
    if os.path.exists(SEQ_FILE):
        with open(SEQ_FILE, 'r') as f:
            try:
                seq = int(f.read().strip())
            except ValueError:
                pass
    seq += 1
    with open(SEQ_FILE, 'w') as f:
        f.write(str(seq))
    return seq

def send_test(name, event_data, modify_after_signing=False):
    print(f"\n--- Test: {name} ---")
    
    # We need to ensure we have a fresh timestamp and a new sequence for each test
    # unless it's a test specifically designed not to have one
    if name != "Stale Message (Should fail STALE TIMESTAMP)" and name != "Replay Attack (Should fail REPLAY)":
        event_data = event_data.copy()
        if name != "Valid Message (Should pass)": # this one sets it directly in the script below
            event_data["sequence"] = get_next_sequence()
        
    # Ensure tests use the exact same logic as sender to generate signatures
    # (JSON needs to be perfectly sorted with exact separator spacing)
    payload_str = json.dumps(event_data, separators=(',', ':'), sort_keys=True)
    signature = generate_signature(SECRET_KEY, payload_str.encode('utf-8'))
    
    if modify_after_signing:
        payload_str = payload_str.replace("5.0", "20.0")
        
    headers = {'Content-Type': 'application/json', 'X-Signature': signature}
    r = requests.post(SERVER_URL, data=payload_str, headers=headers)
    print(f"Result: {r.status_code} - {r.text}")
    return payload_str, signature

now_str = datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
stale_str = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)).isoformat().replace('+00:00', 'Z')

base_event = {
    "device_id": config.get('device_id'),
    "event_id": "demo-attack-001",
    "sequence": get_next_sequence(),
    "timestamp": now_str,
    "event_type": "temperature",
    "simulated": True,
    "data": {"temperature_c": 5.0}
}

# 1. Modified Message (Invalid HMAC)
send_test("Modified Message (Should fail BAD_AUTHENTICATION)", base_event, modify_after_signing=True)

# 2. Stale Timestamp Check
stale_event = base_event.copy()
stale_event["timestamp"] = stale_str
send_test("Stale Message (Should fail STALE TIMESTAMP)", stale_event)

# 3. Valid Message (Sets the sequence)
base_event["sequence"] = get_next_sequence()
base_event["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
valid_payload, valid_sig = send_test("Valid Message (Should pass)", base_event)

# 4. Replay Attack (Exact duplicate of #3)
print(f"\n--- Test: Replay Attack (Should fail REPLAY) ---")
r3 = requests.post(SERVER_URL, data=valid_payload, headers={'Content-Type': 'application/json', 'X-Signature': valid_sig})
print(f"Result: {r3.status_code} - {r3.text}")
