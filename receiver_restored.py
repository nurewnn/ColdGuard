from flask import Flask, request, jsonify
import json
import datetime
import os
from security import load_secret, verify_signature

app = Flask(__name__)

try:
    with open('config.json', 'r') as f:
        config = json.load(f)
except FileNotFoundError:
    print("CRITICAL: config.json not found! Copy config.example.json to config.json.")
    exit(1)

LOG_DIR = os.path.expanduser(config.get('log_dir', '~/.local/state/coldguard'))
AUTHORIZED_CARDS = config.get('authorized_cards', {})
SECRET_KEY = load_secret('~/.config/coldguard/device.key')

TRUSTED_LOG = os.path.join(LOG_DIR, "events.jsonl")
REJECTED_LOG = os.path.join(LOG_DIR, "security_alerts.jsonl")
SEQ_FILE = os.path.join(LOG_DIR, "vm_sequence.txt")

os.makedirs(LOG_DIR, exist_ok=True)

def get_last_sequence():
    if os.path.exists(SEQ_FILE):
        with open(SEQ_FILE, 'r') as f:
            return int(f.read().strip())
    return 0

def save_sequence(seq):
    with open(SEQ_FILE, 'w') as f:
        f.write(str(seq))

def log_event(file_path, data, log_message):
    data['received_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
    with open(file_path, 'a') as f:
        f.write(json.dumps(data) + '\n')
    print(log_message)

@app.route('/events', methods=['POST'])
def receive_event():
    raw_data = request.get_data()
    received_signature = request.headers.get('X-Signature')
    
    # 1. HMAC Verification
    if not verify_signature(SECRET_KEY, raw_data, received_signature):
        log_event(REJECTED_LOG, {"raw_payload": raw_data.decode('utf-8', errors='ignore')}, "REJECTED | BAD_AUTHENTICATION")
        return jsonify({"error": "Forbidden"}), 403
        
    data = json.loads(raw_data)
    
    # 2. Timestamp Freshness Check
    time_str = data.get('timestamp', '').replace('Z', '+00:00')
    try:
        event_time = datetime.datetime.fromisoformat(time_str)
        now = datetime.datetime.now(datetime.timezone.utc)
        if abs((now - event_time).total_seconds()) > 60:
            log_event(REJECTED_LOG, data, "REJECTED | STALE_OR_FUTURE_TIMESTAMP")
            return jsonify({"error": "Stale timestamp"}), 403
    except ValueError:
        return jsonify({"error": "Invalid timestamp format"}), 400

    # 3. Persistent Replay Protection
    in_seq = data.get('sequence', 0)
    last_seq = get_last_sequence()
    if in_seq <= last_seq:
        log_event(REJECTED_LOG, data, f"REJECTED | REPLAY ATTACK (Seq {in_seq} <= {last_seq})")
        return jsonify({"error": "Replay detected"}), 403
    
    # Commit state only after all checks pass
    save_sequence(in_seq)
    
    # 4. Card Permission Checking
    if data.get('event_type') == 'rfid_scan':
        card = data.get('data', {}).get('card_alias')
        if AUTHORIZED_CARDS.get(card) is True:
            data['access_granted'] = True
            log_event(TRUSTED_LOG, data, f"VERIFIED | Seq: {in_seq} | Card Token: {card} | PERMISSION: GRANTED")
        else:
            data['access_granted'] = False
            log_event(TRUSTED_LOG, data, f"VERIFIED | Seq: {in_seq} | Card Token: {card} | PERMISSION: DENIED")
    else:
        log_event(TRUSTED_LOG, data, f"VERIFIED | Seq: {in_seq} | Temp: {data.get('data', {}).get('temperature_c')}C")

    return jsonify({"status": "acknowledged"}), 201

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=18443)
