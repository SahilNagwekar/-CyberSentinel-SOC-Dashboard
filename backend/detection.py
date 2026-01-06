from .database import logs_collection, alerts_collection
from datetime import datetime, timedelta


def create_alert(rule: str, severity: str, details: dict):
    alert = {
        "rule": rule,
        "severity": severity,
        "details": details,
        "status": "open",
        "created_at": datetime.utcnow(),
    }
    alerts_collection.insert_one(alert)


def check_bruteforce(log: dict):
    ip = log.get("source_ip")
    if not ip:
        return

    now = datetime.utcnow()
    window = now - timedelta(minutes=5)

    failed_attempts = logs_collection.count_documents({
        "source_ip": ip,
        "event_type": "login_failed",
        "timestamp": {"$gte": window}
    })

    if failed_attempts >= 5:
        create_alert(
            "Bruteforce login detected",
            "high",
            {"ip": ip, "failed_attempts_last_5m": failed_attempts},
        )


def check_port_scan(log: dict):
    ip = log.get("source_ip")
    if not ip or log.get("event_type") != "port_scan":
        return

    now = datetime.utcnow()
    window = now - timedelta(minutes=1)

    count = logs_collection.count_documents({
        "source_ip": ip,
        "event_type": "port_scan",
        "timestamp": {"$gte": window}
    })

    if count >= 20:
        create_alert(
            "Possible port scan",
            "medium",
            {"ip": ip, "events_last_minute": count},
        )


def check_admin_anomaly(log: dict):
    # Look for admin successful logins from unusual IPs
    if log.get("event_type") != "login_success":
        return

    user = log.get("user")
    ip = log.get("source_ip")
    if user != "admin" or not ip:
        return

    now = datetime.utcnow()
    window = now - timedelta(days=7)

    # known IPs used by admin in last 7 days (before this log)
    known_ips = logs_collection.distinct("source_ip", {
        "user": "admin",
        "event_type": "login_success",
        "timestamp": {"$lt": now, "$gte": window}
    })

    # if there are known IPs and current IP is new → alert
    if known_ips and ip not in known_ips:
        create_alert(
            "New admin login location",
            "high",
            {"ip": ip, "user": user, "previous_ips_last_7d": known_ips},
        )


def run_detections(log: dict):
    # Call all rules here
    check_bruteforce(log)
    check_port_scan(log)
    check_admin_anomaly(log)
