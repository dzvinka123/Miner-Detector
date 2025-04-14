import os
import subprocess
from sys import platform
from dotenv import load_dotenv

load_dotenv()

suspicious_keywords = os.getenv("SUSPICIOUS_KEYWORDS", "")
SUSPICIOUS_KEYWORDS = suspicious_keywords.split(",") if suspicious_keywords else []

LOG_FILES = [
    os.path.expanduser("~/.bash_history"),
    os.path.expanduser("~/.zsh_history"),
    os.path.expanduser("~/.config/"),
    os.path.expanduser("~/.local/share/"),
]

# OS checking
if platform == "darwin":
    LOG_FILES.extend(
        [
            os.path.expanduser("~/Library/Logs/"),
            os.path.expanduser("~/Library/Application Support/"),
        ],
    )


def scan_journalctl():
    try:
        output = subprocess.check_output(
            ["journalctl", "--user", "-n", "1000"], stderr=subprocess.DEVNULL
        )
        for line in output.decode(errors="ignore").splitlines():
            if is_suspicious(line):
                print(f"[!] Suspicious journalctl entry: {line}")
    except Exception:
        pass  # journalctl may not be accessible or installed


def is_suspicious(line):
    return any(keyword in line.lower() for keyword in SUSPICIOUS_KEYWORDS)


def scan_file(file_path):
    try:
        with open(file_path, "r", errors="ignore", encoding="utf8") as f:
            for i, line in enumerate(f, 1):
                if is_suspicious(line):
                    print(f"[!] Suspicious entry in {file_path}:{i}: {line.strip()}")
    except Exception as e:
        print(e)  # Permission errors or binary files


def recursive_scan(directory):
    for root, _, files in os.walk(directory):
        for f in files:
            scan_file(os.path.join(root, f))


def main():
    print("Scanning user-accessible logs...")
    for path in LOG_FILES:
        if os.path.isfile(path):
            scan_file(path)
        elif os.path.isdir(path):
            recursive_scan(path)
    scan_journalctl()
    print("Scan complete.")


if __name__ == "__main__":
    main()
