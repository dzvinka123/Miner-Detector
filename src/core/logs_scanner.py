import os
import time
import subprocess

from sys import platform
from os import access, R_OK
from dotenv import load_dotenv
from core.util import parse_time_threshold

load_dotenv()

suspicious_keywords = os.getenv("SUSPICIOUS_KEYWORDS", "")
log_files = os.getenv("LOG_FILES", "")

SUSPICIOUS_KEYWORDS = suspicious_keywords.split(",") if suspicious_keywords else []
LOG_FILES = [os.path.expanduser(elem) for elem in log_files.split(",")]


def is_suspicious(line):
    """
    Check whether given log has any suspicious keyword.
    """
    return any(keyword in line.lower() for keyword in SUSPICIOUS_KEYWORDS)


def scan_journalctl(report_buffer):
    """
    Scanning Journalctl on Linux systems.
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


def scan_file(file_path, report_buffer, time_thresh="24h"):
    """
    Scanning files by given file path.
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


def logs_scan(logs_files, report_buffer, time):
    """
    Scanning user-accessible directories with cashes and etc.
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
