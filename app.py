from flask import Flask, render_template, request, redirect, url_for, Response

import csv
import io

from parser import parse_log_file
from detector import detect_brute_force
from database import (
    create_database,
    save_alert,
    get_alerts,
    update_alert_status
)

app = Flask(__name__)


def process_logs():

    logs = parse_log_file("logs/security.log")

    alerts = detect_brute_force(logs)

    for alert in alerts:
        save_alert(alert)

    return logs, alerts


create_database()


# ==========================================
# MAIN DASHBOARD
# ==========================================

@app.route("/")
def dashboard():

    logs, alerts = process_logs()

    stored_alerts = get_alerts()

    total_events = len(logs)
    total_alerts = len(stored_alerts)

    critical_threats = 0
    high_threats = 0
    medium_threats = 0
    low_threats = 0

    for alert in stored_alerts:

        if alert["severity"] == "CRITICAL":
            critical_threats += 1

        elif alert["severity"] == "HIGH":
            high_threats += 1

        elif alert["severity"] == "MEDIUM":
            medium_threats += 1

        elif alert["severity"] == "LOW":
            low_threats += 1

    suspicious_ips = len(
        set(alert["ip"] for alert in stored_alerts)
    )

    open_alerts = 0
    investigating_alerts = 0
    resolved_alerts = 0

    for alert in stored_alerts:

        if alert["status"] == "OPEN":
            open_alerts += 1

        elif alert["status"] == "INVESTIGATING":
            investigating_alerts += 1

        elif alert["status"] == "RESOLVED":
            resolved_alerts += 1

    return render_template(
        "dashboard.html",
        total_events=total_events,
        total_alerts=total_alerts,
        critical_threats=critical_threats,
        suspicious_ips=suspicious_ips,
        high_threats=high_threats,
        medium_threats=medium_threats,
        low_threats=low_threats,
        open_alerts=open_alerts,
        investigating_alerts=investigating_alerts,
        resolved_alerts=resolved_alerts,
        alerts=stored_alerts
    )


# ==========================================
# IP INVESTIGATION
# ==========================================
@app.route("/ip/<ip>")
def investigate_ip(ip):

    logs = parse_log_file("logs/security.log")

    ip_logs = []

    for log in logs:

        if log["ip"] == ip:
            ip_logs.append(log)

    # Investigation statistics

    total_events = len(ip_logs)

    failed_logins = 0
    successful_logins = 0
    threats_detected = 0

    detected_threats = []
    risk_level = "LOW"

    for log in ip_logs:

        if log["status"] == "FAILED":
            failed_logins += 1

        elif log["status"] == "SUCCESS":
            successful_logins += 1

        raw_log = log["raw_log"].upper()
        if "MALWARE" in raw_log:
            risk_level = "CRITICAL"

        elif "PORT SCAN" in raw_log and risk_level != "CRITICAL":
            risk_level = "HIGH"

        elif log["status"] == "FAILED" and risk_level == "LOW":
            risk_level = "MEDIUM"

        # Malware detection

        if "MALWARE" in raw_log:

            threats_detected += 1

            detected_threats.append({
                "type": "Malware Detected",
                "severity": "CRITICAL",
                "timestamp": log["timestamp"],
                "ip": log["ip"]
            })

        # Port scan detection

        elif "PORT SCAN" in raw_log:

            threats_detected += 1

            detected_threats.append({
                "type": "Port Scan",
                "severity": "HIGH",
                "timestamp": log["timestamp"],
                "ip": log["ip"]
            })

    return render_template(
        "ip_investigation.html",
        ip=ip,
        logs=ip_logs,
        total_events=total_events,
        failed_logins=failed_logins,
        successful_logins=successful_logins,
        threats_detected=threats_detected,
        detected_threats=detected_threats,
        risk_level=risk_level
    )
# ==========================================
# UPDATE ALERT STATUS
# ==========================================

@app.route("/alert/<int:alert_id>/status", methods=["POST"])
def change_alert_status(alert_id):

    status = request.form.get("status")

    update_alert_status(alert_id, status)

    return redirect(url_for("dashboard"))

# ==========================================
# EXPORT ALERTS TO CSV
# ==========================================

@app.route("/export-alerts")
def export_alerts():

    alerts = get_alerts()

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Timestamp",
        "Severity",
        "Threat",
        "Source IP",
        "Failed Attempts",
        "Status"
    ])

    for alert in alerts:

        writer.writerow([
            alert["id"],
            alert["timestamp"],
            alert["severity"],
            alert["alert_type"],
            alert["ip"],
            alert["failed_attempts"],
            alert["status"]
        ])

    response = Response(
        output.getvalue(),
        mimetype="text/csv"
    )

    response.headers["Content-Disposition"] = (
        "attachment; filename=siem_alerts.csv"
    )

    return response
if __name__ == "__main__":
    app.run(debug=True)