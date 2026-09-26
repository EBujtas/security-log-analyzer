import time
from datetime import datetime, timedelta

from database import (
    initialize_database,
    insert_event,
    insert_alert,
    get_connection
)

LOG_FILE = "sample_auth.log"

BRUTE_FORCE_THRESHOLD = 5
REPEATED_FAILURE_THRESHOLD = 3
DETECTION_WINDOW_MINUTES = 5

CHECK_INTERVAL_SECONDS = 2


def parse_line(line):
    """
    Convert one authentication log line into an event.
    """

    parts = line.strip().split()

    if len(parts) < 5:
        return None

    try:
        timestamp = datetime.strptime(
            f"{parts[0]} {parts[1]}",
            "%Y-%m-%d %H:%M:%S"
        )

        event_type = parts[2]

        username = parts[3].split("=", 1)[1]
        source_ip = parts[4].split("=", 1)[1]

        return {
            "timestamp": timestamp,
            "event_type": event_type,
            "username": username,
            "source_ip": source_ip
        }

    except (ValueError, IndexError):
        print(f"Could not parse line: {line.strip()}")
        return None


def get_recent_failures(source_ip, timestamp):
    """
    Find failed logins from this IP during the
    previous five minutes.
    """

    start_time = timestamp - timedelta(
        minutes=DETECTION_WINDOW_MINUTES
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT timestamp, username
        FROM events
        WHERE source_ip = ?
        AND event_type = 'LOGIN_FAILED'
        AND timestamp >= ?
        AND timestamp <= ?
        ORDER BY timestamp ASC
        """,
        (
            source_ip,
            start_time.strftime("%Y-%m-%d %H:%M:%S"),
            timestamp.strftime("%Y-%m-%d %H:%M:%S")
        )
    )

    results = cursor.fetchall()

    connection.close()

    return results


def alert_exists(alert_type, source_ip, username, timestamp):
    """
    Prevent the collector from repeatedly generating
    the same alert while events continue arriving.
    """

    start_time = timestamp - timedelta(
        minutes=DETECTION_WINDOW_MINUTES
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id
        FROM alerts
        WHERE alert_type = ?
        AND source_ip = ?
        AND username = ?
        AND timestamp >= ?
        LIMIT 1
        """,
        (
            alert_type,
            source_ip,
            username,
            start_time.strftime("%Y-%m-%d %H:%M:%S")
        )
    )

    result = cursor.fetchone()

    connection.close()

    return result is not None


def analyze_event(event):
    """
    Run detection logic against a newly received event.
    """

    source_ip = event["source_ip"]
    username = event["username"]
    timestamp = event["timestamp"]

    recent_failures = get_recent_failures(
        source_ip,
        timestamp
    )

    failure_count = len(recent_failures)

    # Successful authentication following failures
    if (
        event["event_type"] == "LOGIN_SUCCESS"
        and failure_count > 0
    ):

        alert_type = "Failure Followed by Success"

        if not alert_exists(
            alert_type,
            source_ip,
            username,
            timestamp
        ):

            alert = {
                "timestamp": timestamp,
                "severity": "NOTICE",
                "alert_type": alert_type,
                "source_ip": source_ip,
                "username": username,
                "event_count": failure_count,
                "description":
                    f"Successful authentication after "
                    f"{failure_count} recent failed attempts."
            }

            insert_alert(alert)

            print(
                f"[NOTICE] {source_ip} - "
                f"Failure followed by success"
            )

    # Failed authentication detections
    if event["event_type"] == "LOGIN_FAILED":

        if failure_count >= BRUTE_FORCE_THRESHOLD:

            alert_type = "Possible Brute Force"

            if not alert_exists(
                alert_type,
                source_ip,
                username,
                timestamp
            ):

                alert = {
                    "timestamp": timestamp,
                    "severity": "HIGH",
                    "alert_type": alert_type,
                    "source_ip": source_ip,
                    "username": username,
                    "event_count": failure_count,
                    "description":
                        f"{failure_count} failed authentication "
                        f"attempts within "
                        f"{DETECTION_WINDOW_MINUTES} minutes."
                }

                insert_alert(alert)

                print(
                    f"[HIGH] Possible brute force from "
                    f"{source_ip}"
                )

        elif failure_count >= REPEATED_FAILURE_THRESHOLD:

            alert_type = "Repeated Authentication Failures"

            if not alert_exists(
                alert_type,
                source_ip,
                username,
                timestamp
            ):

                alert = {
                    "timestamp": timestamp,
                    "severity": "MEDIUM",
                    "alert_type": alert_type,
                    "source_ip": source_ip,
                    "username": username,
                    "event_count": failure_count,
                    "description":
                        f"{failure_count} failed authentication "
                        f"attempts within "
                        f"{DETECTION_WINDOW_MINUTES} minutes."
                }

                insert_alert(alert)

                print(
                    f"[MEDIUM] Repeated failures from "
                    f"{source_ip}"
                )


def process_line(line):
    """
    Parse, store, and analyze one new log entry.
    """

    event = parse_line(line)

    if event is None:
        return

    insert_event(event)

    print(
        f"[EVENT] "
        f"{event['timestamp']} | "
        f"{event['event_type']} | "
        f"{event['username']} | "
        f"{event['source_ip']}"
    )

    analyze_event(event)


def monitor_log():
    """
    Continuously check the log for newly appended lines.

    The file is opened only long enough to read new data,
    then closed again. This avoids keeping the log locked
    on Windows.
    """

    initialize_database()

    print("=" * 65)
    print("        SECURITY LOG ANALYZER - LIVE COLLECTOR V7")
    print("=" * 65)

    print(f"\nMonitoring: {LOG_FILE}")
    print(
        f"Checking every {CHECK_INTERVAL_SECONDS} seconds."
    )
    print("Press Ctrl+C to stop.\n")

    try:

        # Find the current end of the log.
        # Existing entries will not be processed again.
        with open(
            LOG_FILE,
            "r",
            encoding="utf-8"
        ) as log_file:

            log_file.seek(0, 2)
            last_position = log_file.tell()

        while True:

            # Reopen the file for each check.
            # It closes immediately after reading.
            with open(
                LOG_FILE,
                "r",
                encoding="utf-8"
            ) as log_file:

                log_file.seek(last_position)

                new_lines = log_file.readlines()

                last_position = log_file.tell()

            for line in new_lines:

                if line.strip():
                    process_line(line)

            time.sleep(
                CHECK_INTERVAL_SECONDS
            )

    except FileNotFoundError:

        print(
            f"\n[ERROR] Could not find {LOG_FILE}"
        )

    except KeyboardInterrupt:

        print("\nCollector stopped.")


if __name__ == "__main__":
    monitor_log()