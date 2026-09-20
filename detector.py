from collections import defaultdict


def detect_brute_force(logs):

    failed_attempts = defaultdict(int)
    alerts = []

    for log in logs:

        ip = log["ip"]
        raw_log = log["raw_log"].upper()
        timestamp = log["timestamp"]

        # ----------------------------------
        # CRITICAL: Malware detected
        # ----------------------------------

        if "MALWARE" in raw_log:

            alert = {
                "type": "Malware Detected",
                "ip": ip,
                "failed_attempts": 0,
                "severity": "CRITICAL",
                "status": "OPEN",
                "timestamp": timestamp
            }

            alerts.append(alert)

        # ----------------------------------
        # HIGH: Port Scan detected
        # ----------------------------------

        if "PORT SCAN" in raw_log:

            alert = {
                "type": "Port Scan",
                "ip": ip,
                "failed_attempts": 0,
                "severity": "HIGH",
                "status": "OPEN",
                "timestamp": timestamp
            }

            alerts.append(alert)

        # ----------------------------------
        # Failed login detection
        # ----------------------------------

        if log["status"] == "FAILED":

            failed_attempts[ip] += 1

            # 3 failed attempts = suspicious activity
            if failed_attempts[ip] == 3:

                alert = {
                    "type": "Suspicious Login Activity",
                    "ip": ip,
                    "failed_attempts": 3,
                    "severity": "MEDIUM",
                    "status": "OPEN",
                    "timestamp": timestamp
                }

                alerts.append(alert)

            # 5 failed attempts = brute force
            elif failed_attempts[ip] == 5:

                alert = {
                    "type": "Brute Force",
                    "ip": ip,
                    "failed_attempts": 5,
                    "severity": "HIGH",
                    "status": "OPEN",
                    "timestamp": timestamp
                }

                alerts.append(alert)

    return alerts


if __name__ == "__main__":

    from parser import parse_log_file

    logs = parse_log_file("logs/security.log")

    alerts = detect_brute_force(logs)

    for alert in alerts:
        print(alert)