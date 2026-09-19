# ColdGuard Stage 2 - Trust Package

## 1. Setup the Secret Key (Required on BOTH Pi and VM)
Both programs explicitly load the cryptographic secret from a restricted file. Create it before running the application:

```bash
mkdir -p ~/.config/coldguard
echo "hackathon-super-secret-key-2026" > ~/.config/coldguard/device.key
chmod 600 ~/.config/coldguard/device.key
```

## 2. Configuration & State Management
Copy the example configuration to create your active settings:
```bash
cp config.example.json config.json
```
**Important:** Ensure the `log_dir` path specified in `config.json` exists (e.g., `/var/lib/coldguard` or `~/coldguard_state`). The sender and receiver will write their persistent sequence counters and event logs to this directory.

## 3. Install Dependencies
```bash
pip install -r requirements.txt
```

## 4. Running the Applications
**Start the VM Receiver:**
```bash
python3 receiver.py
```
**Start the Pi Sender:**
```bash
python3 sender.py
```

## 5. Proving Security Controls
Run the test script to prove modified and replayed messages are rejected:
```bash
python3 test_security.py
```
