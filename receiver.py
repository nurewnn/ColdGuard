from flask import Flask, request, jsonify, send_file
import json
import datetime
import os
import requests
import threading
from dotenv import load_dotenv
from security import load_secret, verify_signature

load_dotenv()

app = Flask(__name__)

try:
    with open('config.json', 'r') as f:
        config = json.load(f)
except FileNotFoundError:
    print("CRITICAL: config.json not found! Copy config.example.json to config.json and edit it.")
    exit(1)

LOG_DIR = config.get('log_dir', '/var/lib/coldguard')
AUTHORIZED_CARDS = config.get('authorized_cards', {})
EXPECTED_DEVICE_ID = config.get('device_id')
SECRET_KEY = load_secret('~/.config/coldguard/device.key')

TRUSTED_LOG = os.path.join(LOG_DIR, "events.jsonl")
REJECTED_LOG = os.path.join(LOG_DIR, "security_alerts.jsonl")
SEQ_FILE = os.path.join(LOG_DIR, "vm_sequence.txt")

os.makedirs(LOG_DIR, exist_ok=True)

# Lock for sequence file reading/writing
seq_lock = threading.Lock()

def get_last_sequence():
    if os.path.exists(SEQ_FILE):
        with open(SEQ_FILE, 'r') as f:
            return int(f.read().strip())
    return 0

def save_sequence(seq):
    with open(SEQ_FILE, 'w') as f:
        f.write(str(seq))

def log_event(file_path, data, log_message):
    data['received_at'] = datetime.datetime.utcnow().isoformat() + "Z"
    with open(file_path, 'a') as f:
        f.write(json.dumps(data) + '\n')
    print(log_message)

@app.route('/')
def index():
    return send_file('dashboard2.html')

def read_logs():
    events = []
    if os.path.exists(TRUSTED_LOG):
        with open(TRUSTED_LOG, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    
    if os.path.exists(REJECTED_LOG):
        with open(REJECTED_LOG, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        data = json.loads(line)
                        events.append({
                            "event_type": "alert",
                            "received_at": data.get("received_at", datetime.datetime.utcnow().isoformat() + "Z"),
                            "event_id": data.get("event_id", "SECURITY_ALERT"),
                            "data": {
                                "reason": "Tamper/Replay Detected",
                                "message": "A malicious payload was blocked."
                            }
                        })
                    except json.JSONDecodeError:
                        pass
    
    events.sort(key=lambda x: x.get('received_at', ''))
    return events[-100:]

@app.route('/api/history')
def api_history():
    return jsonify({"events": read_logs()})

@app.route('/api/latest')
def api_latest():
    events = read_logs()
    latest_temp = None
    latest_rfid = None
    for e in reversed(events):
        if not latest_temp and e.get('event_type') == 'temperature':
            latest_temp = e
        if not latest_rfid and e.get('event_type') == 'rfid_scan':
            latest_rfid = e
        if latest_temp and latest_rfid:
            break
    return jsonify({
        "temperature": latest_temp,
        "rfid": latest_rfid
    })

@app.route('/api/analyze')
def api_analyze():
    events = read_logs()
    recent_events = events[-15:]
    
    llm_api_key = os.environ.get("GEMINI_API_KEY")
    if not llm_api_key:
        return jsonify({"analysis": "GEMINI_API_KEY not found in .env file. Analysis unavailable."})
        
    prompt = "You are a security AI. Summarize the following 15 events in a 3-sentence security incident report. Note any temperature anomalies or unauthorized RFID scans:\\n"
    prompt += json.dumps(recent_events, indent=2)
    
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent?key={llm_api_key}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": 800}
        }
        
        # Call Gemini API
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        response_data = response.json()
        
        if response.status_code == 200:
            analysis = response_data['candidates'][0]['content']['parts'][0]['text']
        else:
            analysis = f"AI Error: {response_data.get('error', {}).get('message', 'Unknown error')}"
    except Exception as e:
        analysis = f"Failed to reach Gemini API: {str(e)}"
        
    return jsonify({"analysis": analysis})

@app.route('/events', methods=['POST'])
def receive_event():
    raw_data = request.get_data()
    received_signature = request.headers.get('X-Signature')
    
    if not verify_signature(SECRET_KEY, raw_data, received_signature):
        log_event(REJECTED_LOG, {"raw_payload": raw_data.decode('utf-8', errors='ignore')}, "REJECTED | BAD_AUTHENTICATION")
        return jsonify({"error": "Forbidden"}), 403
        
    try:
        data = json.loads(raw_data)
    except json.JSONDecodeError:
        return jsonify({"error": "Malformed JSON"}), 400
        
    # Input validation
    if not all(k in data for k in ('device_id', 'sequence', 'timestamp', 'event_type', 'data')):
        return jsonify({"error": "Missing required fields"}), 400
        
    if data.get('device_id') != EXPECTED_DEVICE_ID:
        log_event(REJECTED_LOG, data, f"REJECTED | UNKNOWN_DEVICE ({data.get('device_id')})")
        return jsonify({"error": "Unknown device"}), 403
        
    if not isinstance(data.get('sequence'), int):
        return jsonify({"error": "Invalid sequence format"}), 400
        
    # Timestamp Freshness Check
    time_str = data.get('timestamp', '').replace('Z', '+00:00')
    try:
        event_time = datetime.datetime.fromisoformat(time_str)
        now = datetime.datetime.now(datetime.timezone.utc)
        # Allow up to 60 seconds old, or up to 5 seconds into the future
        diff = (now - event_time).total_seconds()
        if diff > 60 or diff < -5:
            log_event(REJECTED_LOG, data, f"REJECTED | STALE_OR_FUTURE_TIMESTAMP (diff: {diff:.1f}s)")
            return jsonify({"error": "Stale timestamp"}), 403
    except ValueError:
        return jsonify({"error": "Invalid timestamp format"}), 400

    in_seq = data.get('sequence')
    
    with seq_lock:
        last_seq = get_last_sequence()
        if in_seq <= last_seq:
            log_event(REJECTED_LOG, data, f"REJECTED | REPLAY ATTACK (Seq {in_seq} <= {last_seq})")
            return jsonify({"error": "Replay detected"}), 403
        
        save_sequence(in_seq)
    
    if data.get('event_type') == 'rfid_scan':
        card = data.get('data', {}).get('card_alias')
        if AUTHORIZED_CARDS.get(card) is True:
            data['access_granted'] = True
            log_event(TRUSTED_LOG, data, f"VERIFIED | Seq: {in_seq} | Card: {card} | PERMISSION: GRANTED")
        else:
            data['access_granted'] = False
            log_event(TRUSTED_LOG, data, f"VERIFIED | Seq: {in_seq} | Card: {card} | PERMISSION: DENIED")
    else:
        log_event(TRUSTED_LOG, data, f"VERIFIED | Seq: {in_seq} | Temp: {data.get('data', {}).get('temperature_c')}C")

    return jsonify({"status": "acknowledged"}), 201

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=18443)
