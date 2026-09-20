import re


def parse_log_file(filename):
    """
    Reads security.log and converts each line
    into a structured log dictionary.
    """

    logs = []

    try:
        with open(filename, "r") as file:

            for index, line in enumerate(file, start=1):

                line = line.strip()

                if not line:
                    continue

                # Extract timestamp
                timestamp_match = re.search(
                    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",
                    line
                )

                if timestamp_match:
                    timestamp = timestamp_match.group(1)
                else:
                    timestamp = "Unknown"

                # Extract IP address
                ip_match = re.search(
                    r"IP:\s*(\d{1,3}(?:\.\d{1,3}){3})",
                    line
                )

                if ip_match:
                    ip = ip_match.group(1)
                else:
                    ip = "Unknown"

                # Detect login status
                if "LOGIN FAILED" in line.upper():
                    status = "FAILED"

                elif "LOGIN SUCCESS" in line.upper():
                    status = "SUCCESS"

                else:
                    status = "UNKNOWN"

                # Extract username
                user_match = re.search(
                    r"USER:\s*(\S+)",
                    line,
                    re.IGNORECASE
                )

                if user_match:
                    user = user_match.group(1)
                else:
                    user = "Unknown"

                # Create structured log
                log = {
                    "id": index,
                    "timestamp": timestamp,
                    "raw_log": line,
                    "ip": ip,
                    "user": user,
                    "status": status
                }

                logs.append(log)

    except FileNotFoundError:

        print(f"Error: Log file '{filename}' not found.")

    except Exception as e:

        print(f"Error while parsing logs: {e}")

    return logs