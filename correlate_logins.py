import json
from pathlib import Path

LOG_FILE = Path("/var/ossec/logs/alerts/alerts.json")


def load_alerts(file_path):
    alerts = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            alert = json.loads(line)
            alerts.append(alert)

    return alerts

def filter_login_alerts(alerts):
    relevant_alerts = []

    for alert in alerts:
        rule_id = str(alert.get("rule", {}).get("id", ""))

        if rule_id in ("100201", "60118"):
            relevant_alerts.append(alert)

    return relevant_alerts
from datetime import datetime


def correlate_logins(alerts):
    detections = []
    brute_force_alerts = {}

    alerts = sorted(
        alerts,
        key=lambda alert: alert["timestamp"]
    )

    for alert in alerts:
        rule_id = str(alert["rule"]["id"])
        agent_id = alert["agent"]["id"]

        username = (
            alert.get("data", {})
            .get("win", {})
            .get("eventdata", {})
            .get("targetUserName", "")
        )

        timestamp = datetime.strptime(
            alert["timestamp"],
            "%Y-%m-%dT%H:%M:%S.%f%z"
        )

        key = (agent_id, username.lower())

        if not username:
            continue

        if rule_id == "100201":
            brute_force_alerts[key] = timestamp

        elif rule_id == "60118":
            if key not in brute_force_alerts:
                continue

            last_brute_force = brute_force_alerts[key]
            time_difference = (
                timestamp - last_brute_force
            ).total_seconds()

            if 0 < time_difference <= 60:
                detections.append({
                    "rule_id": 100202,
                    "agent_id": agent_id,
                    "username": username,
                    "time_difference": time_difference,
                    "timestamp": alert["timestamp"]
                })

                del brute_force_alerts[key]

    return detections

def test_no_false_positive(alerts):
    successful_logins = [
        alert for alert in alerts
        if str(alert["rule"]["id"]) == "60118"
    ]

    detections = correlate_logins(successful_logins)

    if len(detections) == 0:
        print("NEGATIVTEST BESTANDEN: Kein falscher Alarm")
    else:
        print("NEGATIVTEST FEHLGESCHLAGEN")



if __name__ == "__main__":
    alerts = load_alerts(LOG_FILE)
    relevant_alerts = filter_login_alerts(alerts)

    print(f"Relevante Alerts gefunden: {len(relevant_alerts)}")

    for alert in relevant_alerts:
        timestamp = alert.get("timestamp", "unknown")
        rule_id = alert.get("rule", {}).get("id", "unknown")
        agent_id = alert.get("agent", {}).get("id", "unknown")

        username = (
            alert.get("data", {})
            .get("win", {})
            .get("eventdata", {})
            .get("targetUserName", "unknown")
        )

        print(
            f"Time: {timestamp} | "
            f"Rule: {rule_id} | "
            f"Agent: {agent_id} | "
            f"User: {username}"
        )

    detections = correlate_logins(relevant_alerts)

    print(f"\nDetections gefunden: {len(detections)}")

    for detection in detections:
        print(
            f"Detection: {detection['rule_id']} | "
            f"Agent: {detection['agent_id']} | "
            f"User: {detection['username']} | "
            f"Zeitdifferenz: {detection['time_difference']:.2f}s"
        )


    test_no_false_positive(relevant_alerts)
