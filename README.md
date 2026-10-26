# Automated SOAR Playbook for Simulated Endpoint Threat Response

## Project overview
This educational cybersecurity project demonstrates a simple Security Orchestration, Automation and Response (SOAR) workflow. It accepts demo security events, calculates a transparent rule-based risk score, assigns severity, chooses a response, and records actions in an audit log.

**Safety:** Endpoint containment is simulated only. The project does not change real device, account, or network settings.

## Features
- Flask web dashboard
- Sample security events and ability to add demo events
- Risk score from 0 to 100
- Low, Medium, High, and Critical severity labels
- Simulated containment for high/critical events
- Manual-review workflow for medium events
- Audit logging to `data/audit.log`

## Technologies
- Python 3.10+
- Flask
- HTML and CSS
- JSON for sample and event storage

## Rule logic
- 10 or more failed logins: +60
- 5–9 failed logins: +35
- Malware or ransomware event: +70
- Suspicious process or unusual network activity: +35
- Demo known-bad indicator: +40
- Maximum risk score: 100

Severity levels: Low 0–29; Medium 30–59; High 60–79; Critical 80–100.

## Dataset
The project uses a small illustrative sample dataset stored in `data/sample_events.json`. These records are synthetic examples, not real user or organization data. No external dataset is required.

## Setup and run
1. Install Python 3.10 or later.
2. Install dependencies with `python -m pip install -r requirements.txt`.
3. Run `python SoundharyaJ_AutomatedSOAR.py`.
4. Open `http://127.0.0.1:5000` in a browser.

## Limitations
This is a classroom prototype and not a production SOAR platform. It does not integrate with a real SIEM or endpoint agent. Rules may produce false positives or false negatives. Production deployment would require authentication, authorization, secure secret handling, validation, monitoring, and approval controls.

## Suggested future improvements
- Unit tests and richer sample datasets
- Read-only SIEM event ingestion
- Role-based access and authentication
- Approval workflow before any real response
- Dashboard charts and exportable incident reports
