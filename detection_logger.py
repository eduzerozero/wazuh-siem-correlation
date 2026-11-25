import json
from pathlib import Path


DETECTION_LOG = Path(
    "/var/log/wazuh-correlation/detections.json"
)


def build_detection_event(detection):
    return {
        "source": "wazuh-correlation",
        "event_type": "brute_force_successful_login",
        "rule_id": detection["rule_id"],
        "agent_id": detection["agent_id"],
        "username": detection["username"],
        "time_difference": round(
            detection["time_difference"], 2
        ),
        "detection_timestamp": detection["timestamp"],
        "severity": "high"
    }


def write_detection(detection, log_path=DETECTION_LOG):
    event = build_detection_event(detection)

    with open(log_path, "a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")

    return event
