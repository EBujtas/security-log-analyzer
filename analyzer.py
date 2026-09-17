from collections import Counter, defaultdict
from datetime import datetime, timedelta
import csv

LOG_FILE = "sample_auth.log"
REPORT_FILE = "security_report.csv"
ALERT_FILE = "alerts.csv"

# Detection settings
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 5

REPEATED_FAILURE_THRESHOLD = 3
REPEATED_FAILURE_WINDOW_MINUTES = 5


def parse_log(filename):
    """Read the authentication log and convert each line into an event."""

    events = []

    with open(filename, "r", encoding="utf-8") as log_file:
        for line in log_file:
            line = line.strip()

            if not line:
                continue

            parts = line.split()

            if len(parts) < 5:
                continue

            try:
                timestamp = datetime.strptime(
                    f"{parts[0]} {parts[1]}",
                    "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                continue

            event_type = parts[2]

            username = None
            ip_address = None

            for part in parts:
                if part.startswith("user="):
                    username = part.split("=", 1)[1]

                elif part.startswith("ip="):
                    ip_address = part.split("=", 1)[1]

            events.append({
                "timestamp": timestamp,
                "event_type": event_type,
                "username": username,
                "source_ip": ip_address
            })

    return sorted(events, key=lambda event: event["timestamp"])


def detect_threats(events):
    """Analyze authentication events and generate security alerts."""

    alerts = []

    failures_by_ip = defaultdict(list)

    for event in events:
        if event["event_type"] == "LOGIN_FAILED":
            failures_by_ip[event["source_ip"]].append(event)

    # --------------------------------------------------
    # BRUTE FORCE / REPEATED FAILURE DETECTION
    # --------------------------------------------------

    for ip_address, failures in failures_by_ip.items():

        failures = sorted(
            failures,
            key=lambda event: event["timestamp"]
        )

        for start_index in range(len(failures)):

            start_time = failures[start_index]["timestamp"]

            window_events = []

            for event in failures[start_index:]:

                time_difference = (
                    event["timestamp"] - start_time
                )

                if time_difference <= timedelta(
                    minutes=BRUTE_FORCE_WINDOW_MINUTES
                ):
                    window_events.append(event)

                else:
                    break

            # HIGH severity brute force
            if len(window_events) >= BRUTE_FORCE_THRESHOLD:

                users = sorted({
                    event["username"]
                    for event in window_events
                    if event["username"]
                })

                duration = (
                    window_events[-1]["timestamp"]
                    - window_events[0]["timestamp"]
                ).total_seconds()

                alerts.append({
                    "timestamp":
                        window_events[-1]["timestamp"],

                    "severity":
                        "HIGH",

                    "alert_type":
                        "Possible Brute Force",

                    "source_ip":
                        ip_address,

                    "username":
                        ", ".join(users),

                    "event_count":
                        len(window_events),

                    "description":
                        f"{len(window_events)} failed "
                        f"login attempts within "
                        f"{int(duration)} seconds"
                })

                # Only create one brute-force alert per IP
                break

            # MEDIUM repeated failures
            elif len(window_events) >= REPEATED_FAILURE_THRESHOLD:

                duration = (
                    window_events[-1]["timestamp"]
                    - window_events[0]["timestamp"]
                ).total_seconds()

                users = sorted({
                    event["username"]
                    for event in window_events
                    if event["username"]
                })

                alerts.append({
                    "timestamp":
                        window_events[-1]["timestamp"],

                    "severity":
                        "MEDIUM",

                    "alert_type":
                        "Repeated Authentication Failures",

                    "source_ip":
                        ip_address,

                    "username":
                        ", ".join(users),

                    "event_count":
                        len(window_events),

                    "description":
                        f"{len(window_events)} failed "
                        f"login attempts within "
                        f"{int(duration)} seconds"
                })

                break

    # --------------------------------------------------
    # FAILURE FOLLOWED BY SUCCESS
    # --------------------------------------------------

    for success in events:

        if success["event_type"] != "LOGIN_SUCCESS":
            continue

        previous_failures = [
            event
            for event in events
            if (
                event["event_type"] == "LOGIN_FAILED"
                and
                event["source_ip"] == success["source_ip"]
                and
                event["timestamp"] < success["timestamp"]
                and
                success["timestamp"] - event["timestamp"]
                <= timedelta(minutes=5)
            )
        ]

        if previous_failures:

            alerts.append({
                "timestamp":
                    success["timestamp"],

                "severity":
                    "NOTICE",

                "alert_type":
                    "Failure Followed by Success",

                "source_ip":
                    success["source_ip"],

                "username":
                    success["username"],

                "event_count":
                    len(previous_failures),

                "description":
                    f"Successful authentication after "
                    f"{len(previous_failures)} failed "
                    f"attempts within 5 minutes"
            })

    return sorted(
        alerts,
        key=lambda alert: alert["timestamp"]
    )


def create_event_report(events):
    """Save all parsed authentication events."""

    fieldnames = [
        "timestamp",
        "source_ip",
        "username",
        "event_type"
    ]

    with open(
        REPORT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for event in events:

            writer.writerow({
                "timestamp":
                    event["timestamp"].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),

                "source_ip":
                    event["source_ip"],

                "username":
                    event["username"],

                "event_type":
                    event["event_type"]
            })


def create_alert_report(alerts):
    """Save security detections separately from raw events."""

    fieldnames = [
        "timestamp",
        "severity",
        "alert_type",
        "source_ip",
        "username",
        "event_count",
        "description"
    ]

    with open(
        ALERT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for alert in alerts:

            writer.writerow({
                "timestamp":
                    alert["timestamp"].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),

                "severity":
                    alert["severity"],

                "alert_type":
                    alert["alert_type"],

                "source_ip":
                    alert["source_ip"],

                "username":
                    alert["username"],

                "event_count":
                    alert["event_count"],

                "description":
                    alert["description"]
            })


def display_results(events, alerts):
    """Display analysis results in the terminal."""

    successful = sum(
        event["event_type"] == "LOGIN_SUCCESS"
        for event in events
    )

    failed = sum(
        event["event_type"] == "LOGIN_FAILED"
        for event in events
    )

    print("\n" + "=" * 65)
    print("                 SECURITY LOG ANALYZER V5")
    print("=" * 65)

    print("\nEVENT SUMMARY")
    print("-" * 65)

    print(f"Events analyzed:       {len(events)}")
    print(f"Successful logins:     {successful}")
    print(f"Failed logins:         {failed}")
    print(f"Security alerts:       {len(alerts)}")

    severity_counts = Counter(
        alert["severity"]
        for alert in alerts
    )

    print("\nALERT SUMMARY")
    print("-" * 65)

    print(
        f"HIGH:                  "
        f"{severity_counts['HIGH']}"
    )

    print(
        f"MEDIUM:                "
        f"{severity_counts['MEDIUM']}"
    )

    print(
        f"NOTICE:                "
        f"{severity_counts['NOTICE']}"
    )

    print("\nDETECTIONS")
    print("-" * 65)

    if not alerts:
        print("No suspicious authentication patterns detected.")

    for alert in alerts:

        print(
            f"\n[{alert['severity']}] "
            f"{alert['alert_type']}"
        )

        print(
            f"Source IP:   "
            f"{alert['source_ip']}"
        )

        print(
            f"User:        "
            f"{alert['username']}"
        )

        print(
            f"Events:      "
            f"{alert['event_count']}"
        )

        print(
            f"Reason:      "
            f"{alert['description']}"
        )

    print("\n" + "=" * 65)

    print(
        f"Event report created:  "
        f"{REPORT_FILE}"
    )

    print(
        f"Alert report created:  "
        f"{ALERT_FILE}"
    )

    print("                    ANALYSIS COMPLETE")
    print("=" * 65)


def main():

    events = parse_log(LOG_FILE)

    alerts = detect_threats(events)

    create_event_report(events)

    create_alert_report(alerts)

    display_results(events, alerts)


if __name__ == "__main__":
    main()