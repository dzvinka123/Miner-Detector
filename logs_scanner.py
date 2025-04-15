import os
import time
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

# found_miners = []


def is_suspicious(line):
    """
    Check whether given log has any suspicious keyword.
    """
    return any(keyword in line.lower() for keyword in SUSPICIOUS_KEYWORDS)


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


def main():
    """
    Starts execution, contain main logic of program.
    """
    # cli.py
    file_name = "logs_scan.txt"
    write_file = open(file_name, "a", encoding="utf8")

    # cli.py
    # def ask_and_check_root():
    #     response = input("System scan needs root access. Proceed? (y/n): ")
    #     if response.lower() == 'y':
    #         if not is_root():
    #             print("Please re-run the script as root using sudo.")
    #             sys.exit(1)
    #         return True
    #     return False

    if platform == "darwin":
        LOG_FILES.extend(
            [
                os.path.expanduser("~/Library/Logs/"),
                # os.path.expanduser("~/Library/Application Support/"),
                os.path.expanduser("~/Library/LaunchAgents/"),
                # os.path.expanduser("~/Library/Caches/"),
            ],
        )
    elif platform == "linux":
        LOG_FILES.extend(
            [
                os.path.expanduser("~/.profile"),
                os.path.expanduser("~/.bashrc"),
                os.path.expanduser("~/.xsession"),
                os.path.expanduser("~/.xinitrc"),
            ],
        )

    user_accessible_scan(write_file)

    if os.geteuid() == 0:
        if platform == "darwin":
            LOG_DIRS.extend(
                [
                    os.path.expanduser("/var/log/system.log"),
                    os.path.expanduser("/var/log/install.log"),
                    os.path.expanduser("/Library/LaunchAgents/"),
                    os.path.expanduser("~/Library/LaunchDaemons/"),
                ],
            )
        elif platform == "linux":
            LOG_DIRS.extend(
                [
                    os.path.expanduser("/var/log/syslog"),
                    os.path.expanduser("/var/log/messages"),
                    os.path.expanduser("/var/log/auth.log"),
                    os.path.expanduser("/var/log/kern.log"),
                ],
            )

        user_system_wide_scan(write_file)
    else:
        print(
            "System wide logs were not analyzed as current user is not root. Re-run with 'sudo'."
        )

    write_file.close()
    print(f"Results are written inside: {file_name}")
    print("Scan complete.")


if __name__ == "__main__":
    main()
