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

    file = open(LOG_FILE, "r", encoding="utf-8")

    try:
        # Zum aktuellen Dateiende springen
        file.seek(0, 2)

        print("Warte auf neue Wazuh-Alerts...", flush=True)

        while True:
            position = file.tell()
            line = file.readline()

            # Nur vollstaendige Logzeilen verarbeiten
            if not line or not line.endswith("\n"):

                # Unvollstaendige Zeile erneut lesen
                if line:
                    file.seek(position)

                try:
                    current_inode = LOG_FILE.stat().st_ino
                    opened_inode = os.fstat(file.fileno()).st_ino

                    # Logrotation erkennen
                    if current_inode != opened_inode:
                        new_file = open(
                            LOG_FILE, "r", encoding="utf-8"
                        )

                        file.close()
                        file = new_file

                        print(
                            "Logrotation erkannt: Öffne neue Logdatei.",
                            flush=True
                        )

                        continue

                except FileNotFoundError:
                    pass

                time.sleep(0.2 if line else 1)
                continue

            try:
                alert = json.loads(line)

                rule_id = alert.get("rule", {}).get("id", "unknown")
                agent_id = alert.get("agent", {}).get("id", "unknown")
                timestamp = alert.get("timestamp", "unknown")

                # Nur relevante Wazuh-Regeln verarbeiten
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

                # Alte Alerts entfernen
                recent_alerts = [
                    item for item in recent_alerts
                    if datetime.strptime(
                        item["timestamp"],
                        "%Y-%m-%dT%H:%M:%S.%f%z"
                    ) >= cutoff_time
                ]

                # Alte gemeldete Detections entfernen
                expired_keys = [
                    key for key, detection_time
                    in reported_detections.items()
                    if detection_time
                    < cutoff_time - timedelta(minutes=9)
                ]

                for key in expired_keys:
                    del reported_detections[key]

                # Alerts korrelieren
                detections = correlate_logins(recent_alerts)

                for detection in detections:
                    detection_key = (
                        detection["agent_id"],
                        detection["username"].lower(),
                        detection["timestamp"]
                    )

                    # Doppelte Detections verhindern
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

            except json.JSONDecodeError as e:
                print(
                    f"Ungültiger JSON-Alert | "
                    f"Fehler: {e.msg} | "
                    f"Position: {e.pos} | "
                    f"Länge: {len(line)}",
                    flush=True
                )

    finally:
        file.close()


if __name__ == "__main__":
    try:
        watch_logs()
    except KeyboardInterrupt:
        print("\nWazuh-Überwachung sauber beendet.")
