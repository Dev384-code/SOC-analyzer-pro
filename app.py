
import csv
import json
import os
import secrets
from datetime import datetime, timezone 
from io import StringIO
from pathlib import Path

from flask import Flask, Response, flash, jsonify, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

import config
from analyzer.alerts import build_alerts
from analyzer.detector import ATTACK_MAP, calculate_risk, detect
from analyzer.metrics import evaluate_findings
from analyzer.parser import parse_log_file

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_BYTES
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@app.before_request
def require_basic_auth():
    username = os.environ.get("SENTRYLINE_AUTH_USER")
    password = os.environ.get("SENTRYLINE_AUTH_PASSWORD")
    if not username or not password or request.path.startswith("/static/"):
        return None
    auth = request.authorization
    if not auth or not secrets.compare_digest(auth.username or "", username) or not secrets.compare_digest(auth.password or "", password):
        return ("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="Sentryline"'})
    return None


def empty_result():
    return {
        "generated_at": None,
        "source": "No file uploaded",
        "events": [],
        "alerts": [],
        "parse_errors": [],
        "risk_score": 0,
        "summary": {
            "total_events": 0,
            "failed_logins": 0,
            "successful_logins": 0,
            "open_alerts": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "unique_users": 0,
            "unique_ips": 0,
        },
    }


def analyze_log(path):
    events, parse_errors = parse_log_file(path)
    findings = detect(events)
    alerts = sorted(
        build_alerts(findings),
        key=lambda alert: SEVERITY_ORDER.get(alert["severity"].lower(), 99),
    )
    counts = {severity: sum(item["severity"] == severity for item in alerts)
              for severity in ("critical", "high", "medium", "low")}
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": str(path.name),
        "events": events,
        "alerts": alerts,
        "parse_errors": parse_errors,
        "risk_score": calculate_risk(events, findings),
        "summary": {
            "total_events": len(events),
            "failed_logins": sum(event["status"].lower() == "failed" for event in events),
            "successful_logins": sum(event["status"].lower() == "success" for event in events),
            "open_alerts": len(alerts),
            "severity_counts": counts,
            "unique_users": len({event["user"] for event in events}),
            "unique_ips": len({event["ip"] for event in events}),
        },
    }
    config.RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    config.RESULTS_FILE.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def get_results():
    if not config.RESULTS_FILE.exists():
        return empty_result()
    return json.loads(config.RESULTS_FILE.read_text(encoding="utf-8"))


def template_context():
    result = get_results()
    priority_alerts = sorted(
        result["alerts"],
        key=lambda alert: SEVERITY_ORDER.get(alert["severity"].lower(), 99),
    )
    alert_counts = {
        alert_type: sum(alert["type"] == alert_type for alert in result["alerts"])
        for alert_type in ATTACK_MAP
    }
    return {
        "result": result,
        "priority_alerts": priority_alerts,
        "detection_types": ATTACK_MAP,
        "alert_counts": alert_counts,
    }


@app.get("/")
def index():
    return render_template("index.html", **template_context())


@app.get("/dashboard")
def dashboard():
    return render_template("dashboard.html", **template_context())


def benchmark_metrics():
    eval_log = config.BASE_DIR / "tests" / "evaluation_logs.txt"
    ground_truth = config.BASE_DIR / "tests" / "ground_truth.csv"
    if not eval_log.exists() or not ground_truth.exists():
        return None
    events, _ = parse_log_file(eval_log)
    findings = detect(events)
    with ground_truth.open(encoding="utf-8") as f:
        labels = list(csv.DictReader(f))
    return evaluate_findings(findings, labels, total_cases=len(events))


@app.get("/report")
def report():
    context = template_context()
    context["benchmark"] = benchmark_metrics()
    return render_template("report.html", **context)


@app.post("/upload")
def upload():
    uploaded_file = request.files.get("log_file")
    if not uploaded_file or not uploaded_file.filename:
        flash("Choose a .txt or .log file before uploading.", "error")
        return redirect(url_for("dashboard"))

    original_name = secure_filename(uploaded_file.filename)
    extension = Path(original_name).suffix.lower()
    if extension not in config.ALLOWED_LOG_EXTENSIONS:
        flash("Unsupported file type. Upload a .txt or .log file.", "error")
        return redirect(url_for("dashboard"))

    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    stored_name = f"uploaded_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}{extension}"
    upload_path = config.UPLOAD_DIR / stored_name
    uploaded_file.save(upload_path)
    try:
        events, parse_errors = parse_log_file(upload_path)
    except UnicodeDecodeError:
        upload_path.unlink(missing_ok=True)
        flash("The uploaded file is not UTF-8 text. Export it as a text log and try again.", "error")
        return redirect(url_for("dashboard"))
    if not events:
        upload_path.unlink(missing_ok=True)
        flash("No valid log events were found. Check the required log format.", "error")
        return redirect(url_for("dashboard"))

    analyze_log(upload_path)
    message = f"Uploaded {original_name} and analyzed {len(events)} events."
    if parse_errors:
        message += f" Skipped {len(parse_errors)} invalid lines."
    flash(message, "success")
    return redirect(url_for("dashboard"))


@app.get("/api/results")
def api_results():
    return jsonify(get_results())


@app.post("/api/alert/<alert_id>/status")
def update_alert_status(alert_id):
    data = request.get_json(silent=True) or request.form
    new_status = (data.get("status") or "").strip().lower()
    allowed_statuses = {"open", "in_progress", "resolved", "false_positive"}
    if new_status not in allowed_statuses:
        return jsonify({"error": f"Invalid status. Choose from: {', '.join(sorted(allowed_statuses))}"}), 400

    result = get_results()
    target_alert = next((alert for alert in result.get("alerts", []) if alert.get("id") == alert_id), None)
    if not target_alert:
        return jsonify({"error": f"Alert {alert_id} not found"}), 404

    target_alert["status"] = new_status
    target_alert["triage_updated_at"] = datetime.now(timezone.utc).isoformat()
    config.RESULTS_FILE.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return jsonify({"success": True, "alert_id": alert_id, "status": new_status})


@app.post("/load-sample")
def load_sample():
    sample_path = config.BASE_DIR / "tests" / "fixtures" / "sample_incident.log"
    if not sample_path.exists():
        flash("Sample incident log not found in tests/fixtures/.", "error")
        return redirect(url_for("dashboard"))
    analyze_log(sample_path)
    flash("Loaded and analyzed sample multi-stage intrusion log (28 events, 8 ATT&CK techniques).", "success")
    return redirect(url_for("dashboard"))


@app.get("/export/csv")
def export_csv():
    result = get_results()
    alerts = result.get("alerts", [])
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Alert ID", "Severity", "Triage Status", "ATT&CK ID", "ATT&CK Technique", "Tactic", "User", "Source IP", "Timestamp", "Message", "Source Line"])
    for alert in alerts:
        mitre = alert.get("mitre", {})
        writer.writerow([
            alert.get("id", ""),
            alert.get("severity", ""),
            alert.get("status", "open"),
            mitre.get("technique_id", ""),
            mitre.get("technique", ""),
            mitre.get("tactic", ""),
            alert.get("user", ""),
            alert.get("ip", ""),
            alert.get("timestamp", ""),
            alert.get("message", ""),
            alert.get("line", ""),
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=sentryline_alerts_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.csv"}
    )


if __name__ == "__main__":
    app.run(debug=True)
