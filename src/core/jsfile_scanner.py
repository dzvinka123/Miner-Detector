import os
from os import access, R_OK
from dotenv import load_dotenv

load_dotenv()

suspicious_keywords = os.getenv("SUSPICIOUS_KEYWORDS", "")
SUSPICIOUS_KEYWORDS = suspicious_keywords.split(",") if suspicious_keywords else []

def is_suspicious(line):
    """
    Check whether given log has any suspicious keyword.
    """
    return any(keyword in line.lower() for keyword in SUSPICIOUS_KEYWORDS)


def scan_js(js_file, report_buffer):
    if access(js_file, R_OK):
        with open(js_file, "r", encoding="utf-8") as file:
            content = file.read().lower()

        if is_suspicious(js_file):
            report_buffer.write(f"[!] JS file name {js_file} is suspicious.\n")

        if is_suspicious(content):
            report_buffer.write(f"[!] JS content of file {js_file} is suspicious.\n")

    else:
        print(f"Opening {js_file} for reading failed.")
        report_buffer.write(f"[!] File does not have reading access {js_file}")
