# ColdGuard Stage 2 - Advanced Trust Package

## 1. Setup the Secret Keys
The system requires two secrets. We already have matching keys generated in `~/.config/coldguard/device.key` and `~/.config/coldguard/rfid.key`. There is no need to generate new ones.

## 2. Configuration & State Management
Copy the configuration template:
```bash
cp config.example.json config.json
```
The state directory (`~/.local/state/coldguard`) will be automatically created. Sequence counters and logs are stored here permanently.

## 3. Install Dependencies
```bash
pip install -r requirements.txt
```

## 4. Running the Applications
**Start the VM Receiver:**
```bash
python3 receiver.py
```
**Start the Pi Sender (Coordinate with Mechatronics):**
```bash
python3 sender.py
```
*(The sender script is designed to safely recover sequence state. If it crashes, restarting it will resume exactly where it left off, successfully fulfilling the resilience requirement.)*

## 5. Proving Security Controls
Run the comprehensive test script to prove modified, stale, and replayed messages are rejected:
```bash
python3 test_security.py
```

## 6. Implementation Notes & Limitations
* **What is Not Implemented Yet:** This package does not yet provide the stale-data dashboard, RFID behavior alerts, offline queue, or automatic recovery. 
* **Timestamps:** The current timestamp allowance is 60 seconds, rather than the proposed 15-second live-age limit and 5-second future allowance.
