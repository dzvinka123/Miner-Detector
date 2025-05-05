import os
import time
import subprocess
from io import StringIO

from sys import platform
from os import access, R_OK
from dotenv import load_dotenv
from core.util import parse_time_threshold

load_dotenv()

suspicious_keywords = os.getenv("SUSPICIOUS_KEYWORDS", "")
log_files = os.getenv("LOG_FILES", "")

SUSPICIOUS_KEYWORDS = suspicious_keywords.split(",") if suspicious_keywords else []
LOG_FILES = [os.path.expanduser(elem) for elem in log_files.split(",")]


def is_suspicious(line: str) -> bool:
    """
    Check whether the given log contains any suspicious keyword.

    Args:
        line (str): A line of text to be checked for suspicious keywords.

    Returns:
        bool: True if any suspicious keyword is found, False otherwise.
    """
    return any(keyword in line.lower() for keyword in SUSPICIOUS_KEYWORDS)


def scan_journalctl(report_buffer: StringIO) -> None:
    """
    Scans Journalctl logs on Linux systems and writes suspicious entries to the report buffer.

    Args:
        report_buffer (StringIO): A StringIO object used to store the scan results.

    Returns:
        None
    """
    print("Scanning Journalctl logs...")
    try:
        output = subprocess.check_output(
            ["journalctl", "--user", "-n", "1000"], stderr=subprocess.DEVNULL
        )
        for line in output.decode(errors="ignore").splitlines():
            if is_suspicious(line):
                report_buffer.write(f"[!] Suspicious Journalctl entry: {line}\n")
    except Exception as e:
        print(e)
        report_buffer.write(e)
        report_buffer.write("\n")


def scan_file(
    file_path: str, report_buffer: StringIO, time_thresh: str = "24h"
) -> None:
    """
    Scans a file for suspicious entries and writes the results to the report buffer.

    Args:
        file_path (str): The path to the file to be scanned.
        report_buffer (StringIO): A StringIO object used to store the scan results.
        time_thresh (str): A time threshold (default "24h") used to filter file modifications.

    Returns:
        None
    """
    time_threshold_seconds = parse_time_threshold(time_thresh)  # convert to seconds
    last_time = time.time() - time_threshold_seconds
    if access(file_path, R_OK):
        if os.path.getmtime(file_path) > last_time:
            try:
                with open(file_path, "r", errors="ignore", encoding="utf8") as file:
                    for i, line in enumerate(file, 1):
                        if is_suspicious(file_path):
                            report_buffer.write(
                                f"[!] Suspicious entry file {file_path}.\n"
                            )
                            break
                        if is_suspicious(line):
                            report_buffer.write(
                                f"[!] Suspicious entry in {file_path}:{i}: {line.strip()}\n"
                            )
            except Exception as e:
                print(e)
                print(f"[!] File failed openning {file_path}\n")
                report_buffer.write(f"[!] File failed openning {file_path}\n")

    else:
        print(f"[!] File does not have reading access  {file_path}\n")
        report_buffer.write(f"[!] File does not have reading access {file_path}\n")


def logs_scan(logs_files: list, report_buffer: StringIO, time: str) -> None:
    """
    Scans user-accessible directories and files for suspicious entries and writes results to the report buffer.

    Args:
        logs_files (list): A list of paths to files and directories to be scanned.
        report_buffer (StringIO): A StringIO object used to store the scan results.
        time (str): A time threshold used to filter file modifications.

    Returns:
        None
    """
    print("Scanning logs and directories...")
    for path in logs_files:
        if os.path.exists(path):
            if os.path.isfile(path):
                if os.path.getsize(path) < 10 * 1024 * 1024:  # 10MB
                    scan_file(path, report_buffer, time)
                else:
                    report_buffer.write(f"[!] Skipped {path} due to excessive size.\n")
            elif os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for f in files:
                        scan_file(os.path.join(root, f), report_buffer, time)
        else:
            print(f"[!] File does not exist {path}\n")
    if platform == "linux":
        scan_journalctl(report_buffer)
