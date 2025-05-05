import os
import re
import requests
from bs4 import BeautifulSoup

from dotenv import load_dotenv

load_dotenv()

suspicious_keywords = os.getenv("SUSPICIOUS_KEYWORDS", "")
SUSPICIOUS_KEYWORDS = suspicious_keywords.split(",") if suspicious_keywords else []


def is_suspicious(line):
    """
    Check whether given log has any suspicious keyword.
    """
    return any(keyword in line.lower() for keyword in SUSPICIOUS_KEYWORDS)


def scan_url(url, report_buffer):
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
