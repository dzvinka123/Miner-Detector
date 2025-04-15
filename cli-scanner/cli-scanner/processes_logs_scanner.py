import os
import time
import psutil
import subprocess
from sys import platform
from os import access, R_OK
from dotenv import load_dotenv

load_dotenv()

suspicious_keywords = os.getenv("SUSPICIOUS_KEYWORDS", "")
miner_names = os.getenv("MINER_NAMES", "")
log_files = os.getenv("LOG_FILES", "")

LOG_DIRS = []
MINERS = miner_names.split(",") if miner_names else []
SUSPICIOUS_KEYWORDS = suspicious_keywords.split(",") if suspicious_keywords else []
LOG_FILES = [os.path.expanduser(elem) for elem in log_files.split(",")]


def is_suspicious(line):
    """
    Check whether given log has any suspicious keyword.
    """
    return any(keyword in line.lower() for keyword in SUSPICIOUS_KEYWORDS)


def scan_processes(write_file):
    """
    Scanning processes for suspicious keywords.
    """
    print("Scanning processes...")
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            process_name = proc.info["name"].lower()
            for miner in MINERS:
                if miner not in process_name:
                    write_file.write(
                        f"Process: {proc.info["pid"]}, {proc.info["name"]}\n"
                    )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


def scan_journalctl(write_file):
    """
    Scanning Journalctl on Linux systems.
    """
    try:
        output = subprocess.check_output(
            ["journalctl", "--user", "-n", "1000"], stderr=subprocess.DEVNULL
        )
        for line in output.decode(errors="ignore").splitlines():
            if is_suspicious(line):
                write_file.write(f"[!] Suspicious Journalctl entry: {line}\n")
    except Exception as e:
        print(e)
        write_file.write(e)
        write_file.write("\n")


def scan_file(file_path, write_file):
    """
    Scanning user-accessible files with cashes adn etc.
    """
    last_day = time.time() - 86400
    if access(file_path, R_OK):
        if os.path.getmtime(file_path) > last_day:
            try:
                with open(file_path, "r", errors="ignore", encoding="utf8") as file:
                    for i, line in enumerate(file, 1):
                        if is_suspicious(line):
                            write_file.write(
                                f"[!] Suspicious entry in {file_path}:{i}: {line.strip()}\n"
                            )
            except Exception as e:
                print(e)
                print(f"[!] File does not have reading access {file_path}\n")
                write_file.write(f"[!] File does not have reading access {file_path}\n")


def user_accessible_scan(write_file):
    """
    Scanning user-accessible directories with cashes and etc.
    """
    print("Scanning user-accessible directories...")
    for path in LOG_FILES:
        if os.path.isfile(path):
            scan_file(path, write_file)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for f in files:
                    scan_file(os.path.join(root, f), write_file)

    if platform == "linux":
        print("Scanning Journalctl logs...")
        scan_journalctl(write_file)


def tmp_dir_scan(tmp_path, write_file):
    """
    Scanning /tmp directory.
    """
    for root, _, files in os.walk(tmp_path):
        for f in files:
            full_path = os.path.join(root, f)
            try:
                if os.path.getsize(full_path) < 10 * 1024 * 1024:  # 10MB
                    scan_file(full_path, write_file)
            except Exception as e:
                write_file.write(f"[!] Skipped {full_path}: {e}\n")


def var_log_scan(path, write_file, lines=1000):
    """
    Scanning /var/log/... directory.
    """
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = -1024
            data = b""
            while len(data.splitlines()) <= lines and abs(block) < size:
                f.seek(block, os.SEEK_END)
                data = f.read() + data
                block *= 2
            return data.decode(errors="ignore").splitlines()[-lines:]
    except Exception as e:
        write_file.write(f"[!] Could not read {path}: {e}\n")
        return []


def user_system_wide_scan(write_file):
    """
    Scanning system wide logs with root permission.
    """
    print("Scanning system wide logs...")
    for path in LOG_DIRS:
        if path.startswith("/tmp"):
            tmp_dir_scan(path, write_file)
        elif path.startswith("/var/log"):
            var_log_scan(path, write_file)
