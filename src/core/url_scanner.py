import os
import re
import requests
from bs4 import BeautifulSoup

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


def scan_url(url: str, report_buffer) -> None:
    """
    Scan the specified URL for suspicious links, including IP addresses and suspicious keywords.

    Args:
        url (str): The URL to be scanned.
        report_buffer (file-like object): A buffer where suspicious findings are written.

    Returns:
        None
    """
    print(f"Scanning URL: {url}")

    try:
        response = requests.get(url, timeout=10)
        content = response.text.lower()

        soup = BeautifulSoup(content, "html.parser")
        links = soup.find_all("a", href=True)
        suspicious_links = []

        for link in links:
            href = link["href"]

            if re.match(r"http[s]?://\d+\.\d+\.\d+\.\d+", href):
                suspicious_links.append(f"Suspicious IP address : {link}\n")

            elif is_suspicious(href):
                suspicious_links.append(
                    f"Suspicious href {href} found in link: {link}\n"
                )

        if suspicious_links:
            for link in suspicious_links:
                report_buffer.write(link)
        else:
            report_buffer.write("No suspicious IP-based links found.\n")

    except Exception as e:
        report_buffer.write(f"Error while scanning: {e}\n")
