import requests
import time
import uuid
import json
import os
import datetime
from security import load_secret, generate_signature

try:
    import hardware
    IS_SIMULATED = False
except ImportError:
    class hardware:
        @staticmethod
        def read_temperature(): return 6.2
        @staticmethod
        def read_rfid(): return "RAW-UID-A1B2C3D4" # Simulated raw read
    IS_SIMULATED = True

try:
    with open('config.json', 'r') as f:
        config = json.load(f)
except FileNotFoundError:
    print("CRITICAL: config.json not found! Copy config.example.json to config.json.")
    exit(1)

SERVER_URL = config.get('server_url')
DEVICE_ID = config.get('device_id')
LOG_DIR = os.path.expanduser(config.get('log_dir', '~/.local/state/coldguard'))

SECRET_KEY = load_secret('~/.config/coldguard/device.key')
RFID_KEY = load_secret('~/.config/coldguard/rfid.key')

SEQ_FILE = os.path.join(LOG_DIR, "pi_sequence.txt")
os.makedirs(LOG_DIR, exist_ok=True)

def get_next_sequence():
    seq = 0
    if os.path.exists(SEQ_FILE):
        with open(SEQ_FILE, 'r') as f:
            seq = int(f.read().strip())
    seq += 1
    with open(SEQ_FILE, 'w') as f:
        f.write(str(seq))
    return seq

def tokenize_rfid(raw_uid):
    # Hashes the raw UID locally so the network/VM never sees it
    token_hash = generate_signature(RFID_KEY, raw_uid.encode('utf-8'))
    return f"token-{token_hash[:12]}"

def send_event(event_type, payload):
    event = {
        "device_id": DEVICE_ID,
        "event_id": str(uuid.uuid4()),
        "sequence": get_next_sequence(),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'),
        "event_type": event_type,
        "simulated": IS_SIMULATED,
        "data": payload
    }
    
    payload_str = json.dumps(event, separators=(',', ':'), sort_keys=True)
    signature = generate_signature(SECRET_KEY, payload_str.encode('utf-8'))
    headers = {'Content-Type': 'application/json', 'X-Signature': signature}
    
    try:
        response = requests.post(SERVER_URL, data=payload_str, headers=headers, timeout=3)
        print(f"SENT | Seq: {event['sequence']} | ID: {event['event_id']} | Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"FAILED to send Seq {event['sequence']} - Error: {e}")

if __name__ == '__main__':
    print(f"Starting Secure ColdGuard Sender to {SERVER_URL}...")
    if IS_SIMULATED:
        print("WARNING: hardware.py not found. Running in SIMULATION MODE.")
        
    import sys
    test_mode = len(sys.argv) > 1 and sys.argv[1] == '--test-denial'
    test_frozen = len(sys.argv) > 1 and sys.argv[1] == '--test-frozen'

    while True:
        if test_frozen:
            temp = 6.2
        else:
            temp = hardware.read_temperature()
            
        if temp is not None:
            send_event("temperature", {"temperature_c": temp})
        
        if test_mode:
            raw_card = "RAW-UID-DENIED"
        else:
            raw_card = hardware.read_rfid()
            
        if raw_card is not None:
            tokenized_card = tokenize_rfid(raw_card)
            send_event("rfid_scan", {"card_alias": tokenized_card})
            
        time.sleep(5)
