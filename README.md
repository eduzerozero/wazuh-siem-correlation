# Wazuh SIEM – Custom Alert Correlation

A Python-based security monitoring project that extends Wazuh SIEM with custom alert correlation logic.

## Overview

This project detects suspicious Windows login activity by correlating brute-force alerts with subsequent successful authentication events.

The goal is to identify potentially compromised accounts and demonstrate practical skills in SIEM monitoring, log analysis, Python programming, and security detection engineering.

## Detection Logic

The correlation engine monitors the following Wazuh alerts:

| Rule ID | Description |
|---|---|
| 100201 | Custom brute-force detection |
| 60118 | Successful Windows interactive login |
| 100202 | Python-generated correlation detection |

A detection is generated when:

1. A brute-force alert is detected.
2. A successful login occurs within 60 seconds.
3. Both events belong to the same Wazuh agent and username.

The resulting detection indicates suspicious authentication activity, not confirmed account compromise.

## Features

- Real-time monitoring of Wazuh JSON alerts
- Custom Python correlation engine
- Configurable 60-second correlation logic
- Agent and username matching
- Duplicate detection suppression
- Detection of log file replacement and truncation
- Automated correlation tests

## Project Structure

```text
wazuh-siem-correlation/
├── correlate_logins.py
├── watch_alerts.py
├── test_correlation.py
├── .gitignore
└── README.md
```

## Technologies

- Python 3
- Wazuh SIEM
- Linux
- Windows Security Event Logs
- JSON
- Git

## Testing

The project includes tests covering:

- Matching and non-matching usernames
- Different Wazuh agents
- Correlation time windows
- Duplicate detection handling
- Live processing of simulated security alerts
- Log file replacement and truncation

## Current Status

**Development / Homelab Project**

The correlation engine and live monitoring have been tested successfully.

Additional improvements are planned before production use, including robust file handling, log rotation edge cases, and automatic startup using systemd.

## Future Improvements

- Implement a systemd service
- Improve log rotation handling
- Add structured detection logging
- Integrate correlation results into Wazuh dashboards
- Expand automated tests

## Disclaimer

This project was developed for educational purposes in a controlled cybersecurity homelab environment.
