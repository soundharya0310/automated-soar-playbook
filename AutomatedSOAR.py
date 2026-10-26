"""
Automated SOAR Playbook for Simulated Endpoint Threat Response
Cybersecurity Bootcamp Project

Safety: all endpoint containment actions are simulated. This program does not
change real device, account, or network settings.
"""
from flask import Flask, render_template_string, request, redirect, url_for, flash
from pathlib import Path
from datetime import datetime, timezone
import json
import threading

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
EVENTS_FILE = DATA_DIR / "events.json"
SAMPLES_FILE = DATA_DIR / "sample_events.json"
AUDIT_FILE = DATA_DIR / "audit.log"

app = Flask(__name__)
app.secret_key = "change-this-for-any-deployment"
lock = threading.Lock()

PAGE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Automated SOAR Playbook Simulator</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f3f6fb;color:#172033;font-family:Arial,sans-serif}
header{padding:30px max(18px,calc((100% - 1120px)/2));background:#15264b;color:white}
header p{color:#d8e4ff}.notice{background:#fff0c2;color:#674a00;padding:12px;border-radius:8px;font-weight:bold}
main{max-width:1120px;margin:22px auto;padding:0 16px}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.card{background:white;border:1px solid #e0e6f0;border-radius:12px;padding:18px;margin-bottom:16px}
.stat strong{font-size:28px;display:block;margin-top:6px}label{display:block;font-size:13px;margin-bottom:10px}
input,select{width:100%;padding:10px;border:1px solid #cbd4e3;border-radius:6px;margin-top:5px}
button{background:#2457bd;color:white;border:0;border-radius:6px;padding:10px 13px;font-weight:bold;cursor:pointer}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:10px;border-bottom:1px solid #e8edf5;vertical-align:top}
th{color:#64718a}small{display:block;color:#68758a;margin-top:4px}.pill{font-weight:bold;text-transform:uppercase}
.low{color:#167044}.medium{color:#8b6200}.high{color:#ad4b00}.critical{color:#b21c3b}
.flash{padding:10px;background:#e2f7e9;border-radius:7px;margin-bottom:12px}
.muted{color:#64718a;font-size:13px}.formgrid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;align-items:end}
@media(max-width:760px){.stats{grid-template-columns:repeat(2,1fr)}.formgrid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:480px){.formgrid{grid-template-columns:1fr}}
</style></head><body>
<header><p>CYBERSECURITY BOOTCAMP PROJECT</p><h1>Automated SOAR Playbook Simulator</h1>
<p>Rule-based event scoring and simulated incident response.</p>
<div class="notice">SAFE LAB MODE: containment is simulated only. No real endpoint is isolated.</div></header>
<main>
{% with messages = get_flashed_messages() %}{% for message in messages %}<div class="flash">{{message}}</div>{% endfor %}{% endwith %}
<section class="stats">
<div class="card stat">Total events<strong>{{counts.total}}</strong></div>
<div class="card stat">High / Critical<strong>{{counts.high}}</strong></div>
<div class="card stat">Simulated containment<strong>{{counts.contained}}</strong></div>
<div class="card stat">Manual review<strong>{{counts.review}}</strong></div>
</section>
<section class="card"><h2>Add demo event</h2>
<form action="{{url_for('add_event')}}" method="post" class="formgrid">
<label>Event type<select name="event_type"><option value="failed_login_burst">Failed login burst</option>
<option value="suspicious_process">Suspicious process</option><option value="malware_detected">Malware detected (simulation)</option>
<option value="ransomware_alert">Ransomware alert (simulation)</option><option value="unusual_network_activity">Unusual network activity</option></select></label>
<label>Demo endpoint<input name="endpoint" value="DEMO-PC-04" maxlength="80" required></label>
<label>Failed login count<input name="failed_logins" type="number" min="0" max="1000" value="0"></label>
<label>Known-bad indicator?<select name="known_bad_indicator"><option value="no">No</option><option value="yes">Yes (demo flag)</option></select></label>
<button type="submit">Assess event</button></form></section>
<section class="card"><h2>Security events</h2><p class="muted">Use only sample/demo events. Playbook actions are recorded, not applied to real devices.</p>
<div style="overflow-x:auto"><table><thead><tr><th>ID</th><th>Event</th><th>Endpoint</th><th>Risk</th><th>Severity</th><th>Status / response</th><th>Action</th></tr></thead><tbody>
{% for e in events %}<tr><td>#{{e.id}}</td><td>{{e.event_type.replace('_',' ')}}<small>{{e.reasons|join(', ')}}</small></td>
<td>{{e.endpoint}}</td><td>{{e.risk_score}}/100</td><td class="pill {{e.severity}}">{{e.severity}}</td>
<td>{{e.status.replace('_',' ')}}<small>{{e.response_action}}</small></td>
<td><form action="{{url_for('run_playbook')}}" method="post"><input type="hidden" name="event_id" value="{{e.id}}"><button>Run playbook</button></form></td></tr>
{% endfor %}</tbody></table></div></section>
<section class="card"><h2>Response rules</h2><ul>
<li>10+ failed logins: add 60 risk points; 5–9: add 35.</li>
<li>Malware/ransomware event: add 70 points.</li><li>Suspicious process/unusual network activity: add 35 points.</li>
<li>Demo known-bad indicator: add 40 points. Score is capped at 100.</li>
<li>High/Critical: simulated containment; Medium: manual review; Low: log only.</li></ul></section>
<p class="muted">Educational prototype. Not a production SOC/SOAR system.</p>
</main></body></html>
"""

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def read_events():
    DATA_DIR.mkdir(exist_ok=True)
    if not EVENTS_FILE.exists():
        return []
    try:
        return json.loads(EVENTS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

def save_events(events):
    DATA_DIR.mkdir(exist_ok=True)
    with lock:
        EVENTS_FILE.write_text(json.dumps(events, indent=2), encoding="utf-8")

def audit(message):
    DATA_DIR.mkdir(exist_ok=True)
    with lock:
        with AUDIT_FILE.open("a", encoding="utf-8") as f:
            f.write(f"{now()} | {message}\n")

def assess(event):
    score, reasons = 0, []
    kind = str(event.get("event_type", "")).lower()
    failed = int(event.get("failed_logins", 0) or 0)
    if failed >= 10:
        score += 60
        reasons.append("10 or more failed logins")
    elif failed >= 5:
        score += 35
        reasons.append("5 or more failed logins")
    if kind in {"malware_detected", "ransomware_alert"}:
        score += 70
        reasons.append("high-risk event type: " + kind)
    elif kind in {"suspicious_process", "unusual_network_activity"}:
        score += 35
        reasons.append("suspicious event type: " + kind)
    if event.get("known_bad_indicator") is True:
        score += 40
        reasons.append("demo known-bad indicator flag")
    score = min(score, 100)
    severity = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"
    event.update(risk_score=score, severity=severity, reasons=reasons)
    event.setdefault("created_at", now())
    if severity in {"high", "critical"} and event.get("endpoint"):
        event.update(status="contained_simulated", response_action="SIMULATED endpoint isolation")
        audit(f"SIMULATION ONLY: event_id={event.get('id')} endpoint={event['endpoint']} severity={severity}; no settings changed")
    elif severity == "medium":
        event.update(status="review_required", response_action="manual review")
        audit(f"Event {event.get('id')} marked for manual review")
    else:
        event.update(status="logged", response_action="no automated action")
        audit(f"Event {event.get('id')} logged")
    return event

def seed():
    if read_events():
        return
    if SAMPLES_FILE.exists():
        samples = json.loads(SAMPLES_FILE.read_text(encoding="utf-8"))
    else:
        samples = [
            {"id": 1, "event_type": "failed_login_burst", "endpoint": "DEMO-PC-01", "failed_logins": 2, "known_bad_indicator": False},
            {"id": 2, "event_type": "suspicious_process", "endpoint": "DEMO-PC-02", "failed_logins": 6, "known_bad_indicator": False},
            {"id": 3, "event_type": "malware_detected", "endpoint": "DEMO-PC-03", "failed_logins": 0, "known_bad_indicator": True},
            {"id": 4, "event_type": "unusual_network_activity", "endpoint": "DEMO-SRV-01", "failed_logins": 1, "known_bad_indicator": False}
        ]
    save_events([assess(dict(e)) for e in samples])

@app.route("/")
def index():
    seed()
    events = sorted(read_events(), key=lambda e: e.get("created_at", ""), reverse=True)
    counts = {"total": len(events),
              "high": sum(e.get("severity") in {"high", "critical"} for e in events),
              "contained": sum(e.get("status") == "contained_simulated" for e in events),
              "review": sum(e.get("status") == "review_required" for e in events)}
    return render_template_string(PAGE, events=events, counts=counts)

@app.route("/add-event", methods=["POST"])
def add_event():
    events = read_events()
    try:
        failed = max(0, min(1000, int(request.form.get("failed_logins", "0"))))
    except ValueError:
        failed = 0
    next_id = max([int(e.get("id", 0)) for e in events] + [0]) + 1
    e = {"id": next_id, "event_type": request.form.get("event_type", "suspicious_process"),
         "endpoint": (request.form.get("endpoint", "DEMO-PC-01").strip() or "DEMO-PC-01")[:80],
         "failed_logins": failed, "known_bad_indicator": request.form.get("known_bad_indicator") == "yes",
         "created_at": now()}
    events.append(assess(e))
    save_events(events)
    flash(f"Demo event #{next_id} added and assessed.")
    return redirect(url_for("index"))

@app.route("/run-playbook", methods=["POST"])
def run_playbook():
    events = read_events()
    target = request.form.get("event_id", "")
    for i, event in enumerate(events):
        if str(event.get("id")) == target:
            events[i] = assess(dict(event))
            save_events(events)
            flash("Playbook ran in simulation mode only; no real endpoint was isolated.")
            break
    return redirect(url_for("index"))

if __name__ == "__main__":
    DATA_DIR.mkdir(exist_ok=True)
    seed()
    app.run(host="127.0.0.1", port=5000, debug=False)
