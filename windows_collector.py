import subprocess
import sys
import time
from pathlib import Path


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

CHECK_INTERVAL_SECONDS = 10

PROJECT_DIR = Path(__file__).resolve().parent
EXPORTER_FILE = PROJECT_DIR / "windows_exporter.ps1"
IMPORTER_FILE = PROJECT_DIR / "windows_importer.py"


# ---------------------------------------------------------
# RUN POWERSHELL EXPORTER
# ---------------------------------------------------------

def run_exporter():
    """
    Run the PowerShell Windows Security Event exporter.
    """

    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(EXPORTER_FILE)
    ]

    result = subprocess.run(
        command,
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("[ERROR] Windows event export failed.")

        if result.stderr:
            print(result.stderr.strip())

        return False

    return True


# ---------------------------------------------------------
# RUN PYTHON IMPORTER
# ---------------------------------------------------------

def run_importer():
    """
    Import exported Windows events into SQLite.
    """

    command = [
        sys.executable,
        str(IMPORTER_FILE)
    ]

    result = subprocess.run(
        command,
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("[ERROR] Windows event import failed.")

        if result.stderr:
            print(result.stderr.strip())

        return False

    # Only display useful importer activity.
    output = result.stdout.strip()

    if "New events: 0" not in output:
        print(output)

    return True


# ---------------------------------------------------------
# LIVE COLLECTION LOOP
# ---------------------------------------------------------

def monitor_windows_events():

    print("=" * 60)
    print(" SECURITY LOG ANALYZER - WINDOWS COLLECTOR V8")
    print("=" * 60)

    print()
    print("Monitoring Windows authentication events.")
    print(
        f"Checking every "
        f"{CHECK_INTERVAL_SECONDS} seconds."
    )
    print("Press Ctrl+C to stop.")
    print()

    try:

        while True:

            export_success = run_exporter()

            if export_success:
                run_importer()

            time.sleep(
                CHECK_INTERVAL_SECONDS
            )

    except KeyboardInterrupt:

        print()
        print("Windows collector stopped.")


# ---------------------------------------------------------
# PROGRAM ENTRY POINT
# ---------------------------------------------------------

if __name__ == "__main__":
    monitor_windows_events()