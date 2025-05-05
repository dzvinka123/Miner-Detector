import os
from io import StringIO
from os import access, R_OK
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


def scan_js(js_file: str, report_buffer: StringIO) -> None:
    """
    Scans a JavaScript file to check if its name or content contains any suspicious keywords.

    Args:
        js_file (str): The path to the JavaScript file to be scanned.
        report_buffer (StringIO): A StringIO object used to store the scan results.

    Returns:
        None
    """
    if access(js_file, R_OK):
        with open(js_file, "r", encoding="utf-8") as file:
            content = file.read().lower()

        if is_suspicious(js_file):
            report_buffer.write(f"[!] JS file name {js_file} is suspicious.\n")
        else:
            report_buffer.write(f"[!] JS file name {js_file} is NOT suspicious.\n")

        if is_suspicious(content):
            report_buffer.write(f"[!] JS content of file {js_file} is suspicious.\n")
        else:
            report_buffer.write(
                f"[!] JS content of file {js_file} is NOT suspicious.\n"
            )
    else:
        print(f"Opening {js_file} for reading failed.")
        report_buffer.write(f"[!] File does not have reading access {js_file}")
