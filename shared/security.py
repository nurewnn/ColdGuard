import hmac
import hashlib
import os

def load_secret(path):
    expanded_path = os.path.expanduser(path)
    try:
        with open(expanded_path, 'r') as f:
            secret_str = f.read().strip()
            try:
                # Attempt to decode as hex per documented format
                return bytes.fromhex(secret_str)
            except ValueError:
                # Fallback to direct UTF-8 encoding for older/legacy keys
                return secret_str.encode('utf-8')
    except FileNotFoundError:
        print(f"CRITICAL: Secret key file not found at {expanded_path}")
        exit(1)

def generate_signature(secret_key, payload_bytes):
    return hmac.new(secret_key, payload_bytes, hashlib.sha256).hexdigest()

def verify_signature(secret_key, payload_bytes, received_signature):
    if not received_signature:
        return False
    computed_sig = generate_signature(secret_key, payload_bytes)
    return hmac.compare_digest(computed_sig, received_signature)
