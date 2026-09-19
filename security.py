import hmac
import hashlib
import os

SECRET_FILE = os.path.expanduser('~/.config/coldguard/device.key')

def load_secret():
    try:
        with open(SECRET_FILE, 'r') as f:
            return f.read().strip().encode('utf-8')
    except FileNotFoundError:
        print(f"CRITICAL: Secret key file not found at {SECRET_FILE}")
        print("Create it using: mkdir -p ~/.config/coldguard && echo 'your-secret' > ~/.config/coldguard/device.key")
        exit(1)

def generate_signature(secret_key, payload_bytes):
    return hmac.new(secret_key, payload_bytes, hashlib.sha256).hexdigest()

def verify_signature(secret_key, payload_bytes, received_signature):
    if not received_signature:
        return False
    computed_sig = generate_signature(secret_key, payload_bytes)
    return hmac.compare_digest(computed_sig, received_signature)
