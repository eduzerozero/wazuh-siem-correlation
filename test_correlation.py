from datetime import datetime, timedelta
from correlate_logins import correlate_logins

start = datetime.now().astimezone()

def create_alert(rule_id, username, agent_id, timestamp):
    return {
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
        "rule": {"id": str(rule_id)},
        "agent": {"id": agent_id},
        "data": {
            "win": {
                "eventdata": {
                    "targetUserName": username
                }
            }
        }
    }


alerts = [
    create_alert(100201, "wazuh-test", "002", start),
    create_alert(60118, "admin-test", "002", start + timedelta(seconds=30))
]

detections = correlate_logins(alerts)

assert len(detections) == 0, "FEHLER: Falscher Alarm!"

print("TEST BESTANDEN: Unterschiedliche Benutzer erzeugen keinen Alarm.")

# Negativtest: Unterschiedliche Agenten

alerts_different_agents = [
    create_alert(100201, "wazuh-test", "002", start),
    create_alert(
        60118,
        "wazuh-test",
        "003",
        start + timedelta(seconds=30)
    )
]

detections_different_agents = correlate_logins(
    alerts_different_agents
)

assert len(detections_different_agents) == 0, (
    "FEHLER: Unterschiedliche Agenten wurden korreliert!"
)

print("TEST BESTANDEN: Unterschiedliche Agenten erzeugen keinen Alarm.")

# Test: 60-Sekunden-Zeitfenster

for seconds in [30, 60, 61, 120]:
    alerts_time_window = [
        create_alert(
            100201,
            "wazuh-test",
            "002",
            start
        ),
        create_alert(
            60118,
            "wazuh-test",
            "002",
            start + timedelta(seconds=seconds)
        )
    ]

    detections = correlate_logins(alerts_time_window)

    expected = 1 if seconds <= 60 else 0

    assert len(detections) == expected, (
        f"FEHLER bei {seconds} Sekunden: "
        f"Erwartet {expected}, erhalten {len(detections)}"
    )

    print(f"TEST BESTANDEN: Zeitdifferenz {seconds} Sekunden")

# Test: Bereits gemeldete Detections nicht erneut ausgeben

test_alerts = [
    create_alert(100201, "wazuh-test", "002", start),
    create_alert(
        60118,
        "wazuh-test",
        "002",
        start + timedelta(seconds=30)
    )
]

reported_detections = set()
report_count = 0

# Dieselben Alerts zweimal auswerten
for _ in range(2):
    detections = correlate_logins(test_alerts)

    for detection in detections:
        detection_key = (
            detection["agent_id"],
            detection["username"].lower(),
            detection["timestamp"]
        )

        if detection_key in reported_detections:
            continue

        reported_detections.add(detection_key)
        report_count += 1

assert report_count == 1, (
    f"FEHLER: Detection wurde {report_count} Mal gemeldet!"
)

print("TEST BESTANDEN: Detection wird nur einmal gemeldet.")

# Test: Alte Alerts aus dem Speicher entfernen

from datetime import datetime, timedelta

test_alerts = [
    create_alert(100201, "wazuh-test", "002", start),
    create_alert(
        60118,
        "wazuh-test",
        "002",
        start + timedelta(seconds=120)
    )
]

current_time = start + timedelta(seconds=120)
cutoff_time = current_time - timedelta(seconds=60)

filtered_alerts = [
    alert for alert in test_alerts
    if datetime.strptime(
        alert["timestamp"],
        "%Y-%m-%dT%H:%M:%S.%f%z"
    ) >= cutoff_time
]

assert len(filtered_alerts) == 1, (
    "FEHLER: Alte Alerts wurden nicht korrekt entfernt!"
)

assert len(correlate_logins(filtered_alerts)) == 0, (
    "FEHLER: Unerwartete Detection nach Speicherbereinigung!"
)

print("TEST BESTANDEN: Alte Alerts werden entfernt.")
