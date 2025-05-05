import os
import psutil
from dotenv import load_dotenv

load_dotenv()

suspicious_keywords = os.getenv("SUSPICIOUS_KEYWORDS", "")
SUSPICIOUS_KEYWORDS = suspicious_keywords.split(",") if suspicious_keywords else []


def is_suspicious(line: str) -> bool:
    """
    Check whether the given log contains any suspicious keyword.

    Args:
        line (str): A line of text to be checked for suspicious keywords.

    Returns:
        bool: True if any suspicious keyword is found, False otherwise.
    """
    return any(keyword in line.lower() for keyword in SUSPICIOUS_KEYWORDS)


def processes_scan(report_buffer) -> None:
    """
    Scan running processes for suspicious keywords in the process name or executable.

    Args:
        report_buffer (file-like object): A buffer where suspicious process information is written.

    Returns:
        None
    """
    print("Scanning processes...")
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            process_name = proc.info["name"].lower()
            process_exe = (
                proc.info["exe"].lower() if proc.info["exe"] is not None else ""
            )
            if is_suspicious(process_name) or is_suspicious(process_exe):
                cpu = proc.cpu_percent(interval=None)
                report_buffer.write(
                    f"Process {proc.info['pid']}: {proc.info['name']}\n executable: {proc.info['exe']}\n CPU percentage: {cpu}%\n"
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
