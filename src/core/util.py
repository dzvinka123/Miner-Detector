import re
import os
import sys
import requests


def parse_time_threshold(time_str):
    """
    Convert a string like '24h', '7d', '30m' into seconds.
    Supported suffixes: s (seconds), m (minutes), h (hours), d (days)
    """
    pattern = r"^(\d+)([smhd])$"
    match = re.match(pattern, time_str.strip().lower())
    if not match:
        raise ValueError(
            f"Invalid time format: {time_str}. Use formats like '30m', '24h', '7d'."
        )

    value, unit = match.groups()
    value = int(value)

    multiplier = {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
    }

    return value * multiplier[unit]


def ask_and_check_root():
    """
    To get or deny access for user.
    """
    response = input("System scan needs root access. Proceed? (y/n): ")
    if response.lower() == "y":
        if not os.geteuid() == 0:
            print("Please re-run the script as root using 'sudo'.")
            sys.exit(1)
        return True
    return False


def send_report_to_server(report_text, server_url="http://localhost:5555/report"):
    try:
        response = requests.post(server_url, data=report_text.encode("utf-8"))
        if response.status_code == 200:
            print("[✓] Report sent successfully.")
            return 200
        else:
            print(f"[!] Failed to send report. Status: {response.status_code}")
    except Exception as e:
        print(f"[!] Error sending report: {e}")
