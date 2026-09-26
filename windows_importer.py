import csv

from database import (
    initialize_windows_events_table,
    insert_windows_event
)

from windows_detection import (
    analyze_windows_event
)


CSV_FILE = "windows_auth.csv"


def import_windows_events():

    initialize_windows_events_table()

    imported = 0
    duplicates = 0

    with open(
        CSV_FILE,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as csv_file:

        reader = csv.DictReader(csv_file)

        for row in reader:

            event_id = int(row["EventID"])

            if event_id == 4624:
                event_type = "LOGIN_SUCCESS"

            elif event_id == 4625:
                event_type = "LOGIN_FAILED"

            else:
                continue

            event = {
                "timestamp": row["TimeCreated"],
                "windows_event_id": event_id,
                "record_id": int(row["RecordID"]),
                "username": row["Username"],
                "source_ip": row["SourceIP"],
                "logon_type": row["LogonType"],
                "event_type": event_type
            }

            if insert_windows_event(event):
                imported += 1

                print(
                    f"[IMPORTED] "
                    f"{event_type} | "
                    f"{event['username']} | "
                    f"{event['source_ip']} | "
                    f"Record {event['record_id']}"
                )

                analyze_windows_event(event)

            else:
                duplicates += 1

    print()
    print("=" * 50)
    print("WINDOWS IMPORT COMPLETE")
    print("=" * 50)

    print(f"New events: {imported}")
    print(f"Duplicates ignored: {duplicates}")


if __name__ == "__main__":
    import_windows_events()