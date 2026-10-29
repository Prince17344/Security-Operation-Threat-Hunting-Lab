
import csv
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, deque

PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_DIR / "data" / "soc_windows_auth_sample.csv"
REPORT_FILE = PROJECT_DIR / "reports" / "detection_results.csv"

THRESHOLD = 5
WINDOW = timedelta(minutes=5)


def analyze_logins():
    events = []
    alerts = []

    with DATA_FILE.open("r", newline="", encoding="utf-8-sig") as file:
        for row in csv.DictReader(file):
            events.append({
                "time": datetime.fromisoformat(
                    row["timestamp"].strip().replace("Z", "+00:00")
                ),
                "event_code": row["EventCode"].strip(),
                "ip": row["src_ip"].strip(),
                "user": row["user"].strip()
            })

    events.sort(key=lambda e: e["time"])
    failures = defaultdict(deque)
    alerted = set()

    print(f"Total events analyzed: {len(events)}")

    for event in events:
        key = (event["ip"], event["user"])
        recent = failures[key]

        while recent and event["time"] - recent[0] > WINDOW:
            recent.popleft()

        if event["event_code"] == "4625":
            recent.append(event["time"])

            if len(recent) >= THRESHOLD and key not in alerted:
                alerts.append({
                    "timestamp": event["time"].isoformat(sep=" "),
                    "alert_type": "Potential Brute Force",
                    "source_ip": event["ip"],
                    "username": event["user"],
                    "failed_attempts": len(recent),
                    "severity": "Medium"
                })
                print(
                    f"[ALERT] {event['ip']} - {event['user']}: "
                    f"{len(recent)} failures"
                )
                alerted.add(key)

        elif event["event_code"] == "4624":
            if len(recent) >= THRESHOLD:
                alerts.append({
                    "timestamp": event["time"].isoformat(sep=" "),
                    "alert_type": "Failed Logins Followed by Success",
                    "source_ip": event["ip"],
                    "username": event["user"],
                    "failed_attempts": len(recent),
                    "severity": "High"
                })
                print(
                    f"[HIGH PRIORITY] Successful login from "
                    f"{event['ip']} after {len(recent)} failures"
                )

            recent.clear()
            alerted.discard(key)

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "timestamp", "alert_type", "source_ip",
        "username", "failed_attempts", "severity"
    ]

    with REPORT_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(alerts)

    print(f"\nTotal alerts: {len(alerts)}")
    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    analyze_logins()
  