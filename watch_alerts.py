from datetime import datetime, timedelta
import json
import time
from pathlib import Path
from correlate_logins import correlate_logins
import os

LOG_FILE = Path("/var/ossec/logs/alerts/alerts.json")

def watch_logs():
    recent_alerts = []
    reported_detections = {}

    with open(LOG_FILE, "r", encoding="utf-8") as file:

        # Zum aktuellen Dateiende springen
        file.seek(0, 2)

        print("Warte auf neue Wazuh-Alerts...", flush=True)

        while True:
            line = file.readline()

            if not line:
                # Prüfen, ob Wazuh die Logdatei ausgetauscht hat
                try:
                    current_inode = LOG_FILE.stat().st_ino
                    opened_inode = file.fileno()

                    if current_inode != opened_inode:
                        print(
                            "Logrotation erkannt: Öffne neue Logdatei.",
                            flush=True
                        )

                        file.close()
                        file = open(LOG_FILE, "r", encoding="utf-8")

                except FileNotFoundError:
                    print("Logdatei momentan nicht vorhanden.")

                time.sleep(1)
                continue

            try:
                alert = json.loads(line)

                rule_id = alert.get("rule", {}).get("id", "unknown")
                agent_id = alert.get("agent", {}).get("id", "unknown")
                timestamp = alert.get("timestamp", "unknown")

                if str(rule_id) not in ("100201", "60118"):
                                    continue
                print(
                    f"Neuer Alert | "
                    f"Rule: {rule_id} | "
                    f"Agent: {agent_id} | "
                    f"Time: {timestamp}",
                    flush=True
                )

                recent_alerts.append(alert)

                current_time = datetime.strptime(
                    alert["timestamp"],
                    "%Y-%m-%dT%H:%M:%S.%f%z"
                )

                cutoff_time = current_time - timedelta(seconds=60)

                recent_alerts = [
                    item for item in recent_alerts
                    if datetime.strptime(
                        item["timestamp"],
                        "%Y-%m-%dT%H:%M:%S.%f%z"
                    ) >= cutoff_time
                ]

                # Alte gemeldete Detections entfernen
                expired_keys = [
                    key for key, detection_time in reported_detections.items()
                    if detection_time < cutoff_time - timedelta(minutes=9)
                ]

                for key in expired_keys:
                    del reported_detections[key]

                detections = correlate_logins(recent_alerts)

                for detection in detections:
                    detection_key = (
                        detection["agent_id"],
                        detection["username"].lower(),
                        detection["timestamp"]
                    )

                    if detection_key in reported_detections:
                        continue

                    reported_detections[detection_key] = datetime.strptime(
                        detection["timestamp"],
                        "%Y-%m-%dT%H:%M:%S.%f%z"
                    )

                    print(
                        f"DETECTION {detection['rule_id']} | "
                        f"Agent: {detection['agent_id']} | "
                        f"User: {detection['username']} | "
                        f"Zeitdifferenz: {detection['time_difference']:.2f}s",
                        flush=True
                    )

            except json.JSONDecodeError:
                print("Ungültiger JSON-Alert übersprungen.")


if __name__ == "__main__":
    try:
        watch_logs()
    except KeyboardInterrupt:
        print("\nWazuh-Überwachung sauber beendet.")
