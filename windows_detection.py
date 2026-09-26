from datetime import datetime, timedelta

from database import (
    get_connection,
    insert_alert
)


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

DETECTION_WINDOW_MINUTES = 5
REPEATED_FAILURE_THRESHOLD = 3
BRUTE_FORCE_THRESHOLD = 5


# ---------------------------------------------------------
# TIMESTAMP CONVERSION
# ---------------------------------------------------------

def parse_timestamp(timestamp):
    """
    Convert a Windows timestamp from SQLite into datetime.
    """

    formats = [
        "%m/%d/%Y %I:%M:%S %p",
        "%Y-%m-%d %H:%M:%S"
    ]

    for date_format in formats:
        try:
            return datetime.strptime(
                timestamp,
                date_format
            )
        except ValueError:
            continue

    return None


# ---------------------------------------------------------
# RECENT FAILURE LOOKUP
# ---------------------------------------------------------

def get_recent_windows_failures(
    source_ip,
    current_time
):
    """
    Find recent Windows LOGIN_FAILED events
    from the same source IP.
    """

    start_time = (
        current_time -
        timedelta(
            minutes=DETECTION_WINDOW_MINUTES
        )
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            timestamp,
            username,
            source_ip
        FROM windows_events
        WHERE event_type = 'LOGIN_FAILED'
          AND source_ip = ?
    """, (
        source_ip,
    ))

    rows = cursor.fetchall()
    connection.close()

    recent_failures = []

    for row in rows:

        event_time = parse_timestamp(
            row[0]
        )

        if event_time is None:
            continue

        if (
            start_time
            <= event_time
            <= current_time
        ):
            recent_failures.append(row)

    return recent_failures


# ---------------------------------------------------------
# DETECTION ENGINE
# ---------------------------------------------------------

def analyze_windows_event(event):
    """
    Analyze a Windows authentication event
    for suspicious behavior.
    """

    timestamp = parse_timestamp(
        event["timestamp"]
    )

    if timestamp is None:
        return

    source_ip = event["source_ip"]
    username = event["username"]
    event_type = event["event_type"]

    # Ignore authentication events that do not
    # have a meaningful remote source.
    if source_ip in (
        "LOCAL",
        "127.0.0.1",
        "::1",
        "",
        None
    ):
        return

    failures = get_recent_windows_failures(
        source_ip,
        timestamp
    )

    failure_count = len(failures)

    # -----------------------------------------------------
    # FAILURE DETECTION
    # -----------------------------------------------------

    if event_type == "LOGIN_FAILED":

        if (
            failure_count
            >= BRUTE_FORCE_THRESHOLD
        ):

            alert = {
                "timestamp": timestamp,
                "severity": "HIGH",
                "alert_type":
                    "WINDOWS_BRUTE_FORCE",
                "source_ip": source_ip,
                "username": username,
                "event_count": failure_count,
                "description":
                    "Multiple Windows authentication "
                    "failures detected from the same "
                    "source IP."
            }

            insert_alert(alert)

            print(
                f"[HIGH] Windows brute-force "
                f"pattern | {source_ip} | "
                f"{failure_count} failures"
            )

        elif (
            failure_count
            >= REPEATED_FAILURE_THRESHOLD
        ):

            alert = {
                "timestamp": timestamp,
                "severity": "MEDIUM",
                "alert_type":
                    "WINDOWS_REPEATED_FAILURES",
                "source_ip": source_ip,
                "username": username,
                "event_count": failure_count,
                "description":
                    "Repeated Windows authentication "
                    "failures detected from the same "
                    "source IP."
            }

            insert_alert(alert)

            print(
                f"[MEDIUM] Repeated Windows "
                f"failures | {source_ip} | "
                f"{failure_count} failures"
            )

    # -----------------------------------------------------
    # FAILURE FOLLOWED BY SUCCESS
    # -----------------------------------------------------

    elif (
        event_type == "LOGIN_SUCCESS"
        and failure_count > 0
    ):

        alert = {
            "timestamp": timestamp,
            "severity": "NOTICE",
            "alert_type":
                "WINDOWS_FAILURE_THEN_SUCCESS",
            "source_ip": source_ip,
            "username": username,
            "event_count": failure_count,
            "description":
                "Successful Windows authentication "
                "occurred after recent failures from "
                "the same source IP."
        }

        insert_alert(alert)

        print(
            f"[NOTICE] Windows success after "
            f"failures | {source_ip}"
        )