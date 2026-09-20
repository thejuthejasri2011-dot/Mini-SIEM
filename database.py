import sqlite3


DATABASE = "siem.db"


def create_database():
    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    # Create alerts table if it does not exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            ip TEXT,
            failed_attempts INTEGER,
            severity TEXT,
            status TEXT,
            timestamp TEXT
        )
    """)

    # Add timestamp column to an existing database
    cursor.execute("PRAGMA table_info(alerts)")

    columns = [column[1] for column in cursor.fetchall()]

    if "timestamp" not in columns:
        cursor.execute(
            "ALTER TABLE alerts ADD COLUMN timestamp TEXT"
        )

    connection.commit()
    connection.close()


def save_alert(alert):
    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT id FROM alerts
        WHERE alert_type = ?
        AND ip = ?
        AND failed_attempts = ?
        AND severity = ?
    """, (
        alert["type"],
        alert["ip"],
        alert["failed_attempts"],
        alert["severity"]
    ))

    existing_alert = cursor.fetchone()

    if existing_alert:
        connection.close()
        return

    cursor.execute("""
        INSERT INTO alerts
        (alert_type, ip, failed_attempts, severity, status, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert["type"],
        alert["ip"],
        alert["failed_attempts"],
        alert["severity"],
        alert["status"],
        alert["timestamp"]
    ))

    connection.commit()
    connection.close()


def get_alerts():
    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM alerts
        ORDER BY id DESC
    """)

    alerts = cursor.fetchall()

    connection.close()

    return alerts

def update_alert_status(alert_id, status):

    allowed_statuses = ["OPEN", "INVESTIGATING", "RESOLVED"]

    if status not in allowed_statuses:
        return False

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE alerts
        SET status = ?
        WHERE id = ?
    """, (
        status,
        alert_id
    ))

    connection.commit()

    updated = cursor.rowcount > 0

    connection.close()

    return updated


if __name__ == "__main__":

    from parser import parse_log_file
    from detector import detect_brute_force

    create_database()

    logs = parse_log_file("logs/security.log")

    alerts = detect_brute_force(logs)

    for alert in alerts:
        save_alert(alert)

    print("Alerts saved successfully!")