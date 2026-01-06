import requests
import time
import re
from datetime import datetime

API_BASE = "http://127.0.0.1:8000"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
GEO_URL = "http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon"

# How many IPs per run to ingest (to avoid hammering APIs)
MAX_IPS_PER_RUN = 30
SLEEP_BETWEEN_IPS = 2   # seconds
SLEEP_BETWEEN_RUNS = 600  # 10 minutes between full refreshes


def fetch_feodo_ips():
    try:
        resp = requests.get(FEODO_URL, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        print("Error fetching Feodo blocklist:", e)
        return []

    text = resp.text
    # Extract all IPv4 addresses
    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    # Deduplicate while preserving order
    seen = set()
    unique_ips = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)
    return unique_ips[:MAX_IPS_PER_RUN]


def geo_lookup(ip):
    try:
        resp = requests.get(GEO_URL.format(ip=ip), timeout=5)
        data = resp.json()
        if data.get("status") != "success":
            return None
        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
        }
    except Exception as e:
        print(f"Geo lookup failed for {ip}:", e)
        return None


def send_to_soc(ip, location):
    timestamp = datetime.utcnow().replace(microsecond=0).isoformat()

    payload = {
        "timestamp": timestamp,
        "source": "feodotracker",
        "source_ip": ip,
        "dest_ip": "0.0.0.0",
        "user": "threat_feed",
        "event_type": "threat_intel_ip",
        "status": "malicious",
        "severity": "high",
        "raw": {
            "feed": "feodotracker",
            "location": location,
        },
    }

    try:
        r = requests.post(f"{API_BASE}/logs", json=payload, timeout=10)
        print(f"[{r.status_code}] sent threat intel log for {ip} ({location})")
    except Exception as e:
        print("Error sending log:", e)


def run_once():
    print("Fetching Feodo threat feed...")
    ips = fetch_feodo_ips()
    print(f"Got {len(ips)} IPs from feed")

    for ip in ips:
        loc = geo_lookup(ip)
        if not loc:
            # still send log without location if you want, or skip
            print(f"Skipping {ip}, no geo info")
            continue
        send_to_soc(ip, loc)
        time.sleep(SLEEP_BETWEEN_IPS)


if __name__ == "__main__":
    print("Starting threat feed ingestor. Ctrl+C to stop.")
    while True:
        run_once()
        print(f"Sleeping {SLEEP_BETWEEN_RUNS} seconds before next pull...")
        time.sleep(SLEEP_BETWEEN_RUNS)
