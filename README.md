# 🛡️ Mini-SIEM

A lightweight Security Information and Event Management (SIEM) system built with Python and Flask.

Mini-SIEM parses security logs, detects suspicious activity, stores security alerts in SQLite, and provides a professional SOC-style dashboard for monitoring and investigating threats.

---

## 🚀 Features

- 🔍 Security log parsing
- 🚨 Automated threat detection
- 🔐 Brute-force login detection
- 🦠 Malware detection
- 🔎 Port-scan detection
- 📊 Security Operations Center (SOC) dashboard
- 🌐 IP investigation
- 🎯 Threat severity classification
- 🔄 Alert status management
- 🔎 Alert filtering
- 📥 CSV alert export
- 📈 Threat activity visualization
- 💾 SQLite database storage

---

## 🧠 Threat Detection

Mini-SIEM currently detects:

| Threat | Severity |
|---|---|
| Suspicious Login Activity | MEDIUM |
| Brute Force | HIGH |
| Port Scan | HIGH |
| Malware Detected | CRITICAL |

The detection engine analyzes security log events and generates structured alerts automatically.

---

## 🖥️ Dashboard

The dashboard provides a SOC-style monitoring interface containing:

- Total security events
- Total alerts
- Critical threats
- Suspicious IPs
- Open alerts
- Investigating alerts
- Resolved alerts
- Threat distribution
- Threat activity timeline
- Recent security alerts

---

## 🔎 IP Investigation

Security analysts can select a source IP from the alert table to investigate activity associated with that IP address.

The investigation page displays:

- Total events
- Failed login attempts
- Successful logins
- Detected threats
- Threat severity
- Event timestamps
- Source IP information

---

## 📊 Alert Management

Each alert can be assigned one of three statuses:

- 🔴 OPEN
- 🟠 INVESTIGATING
- 🟢 RESOLVED

Alert status changes are stored in the SQLite database and persist after refreshing the dashboard.

---

## 📥 CSV Export

Security alerts can be exported as a CSV file for further analysis, reporting, or incident documentation.

---

##

👩‍💻 Author
Theja Sri
B.Tech Computer Science Engineering
Cybersecurity Enthusiast
⭐ If you find this project useful, consider giving the repository a star!

