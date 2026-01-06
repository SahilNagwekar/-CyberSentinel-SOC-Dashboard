import requests
import random
import time
from datetime import datetime

API_BASE = "http://127.0.0.1:8000"

SOURCES = ["vpn", "firewall", "webserver"]
EVENT_TYPES = ["login_failed", "login_success", "port_scan", "page_view"]
USERS = ["sahil", "admin", "john", "guest"]
IPS = [
    "10.0.0.55",
    "10.0.0.12",
    "192.168.1.10",
    "172.16.0.5",
    "203.0.113.9",
]

def generate_log():
    # ISO timestamp like 2025-01-01T10:00:00
    timestamp = datetime.utcnow().replace(microsecond=0).isoformat()

    source = random.choice(SOURCES)
    event_type = random.choice(EVENT_TYPES)
    user = random.choice(USERS)
    source_ip = random.choice(IPS)

    # make more failed logins from one IP so our brute-force rule fires
    if random.random() < 0.3:
        event_type = "login_failed"
        source_ip = "10.0.0.55"

    payload = {
        "timestamp": timestamp,
        "source": source,
        "source_ip": source_ip,
        "dest_ip": "10.0.0.1",
        "user": user,
        "event_type": event_type,
        "status": "failed" if event_type == "login_failed" else "ok",
        "severity": "high" if event_type in ["port_scan", "login_failed"] else "low",
        "raw": {}
    }

    try:
        r = requests.post(f"{API_BASE}/logs", json=payload)
        print(f"[{r.status_code}] sent log: {payload}")
    except Exception as e:
        print("Error sending log:", e)

if __name__ == "__main__":
    print("Starting log generator… Ctrl+C to stop.")
    while True:
        generate_log()
        time.sleep(3)   # send one log every 3 seconds
