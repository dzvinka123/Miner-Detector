import os
import sys
from io import StringIO

from sys import platform
from dotenv import load_dotenv
from core.cpu_gpu_scanner import (
    scan_cpu,
    scan_gpu,
)
from core.jsfile_scanner import scan_js
from core.logs_scanner import logs_scan
from core.network_scanner import (
    scan_hosts_for_miner_ports,
    discover_active_hosts,
)
from core.processes_scannes import processes_scan
from core.url_scanner import scan_url
from core.util import send_report_to_server

load_dotenv()
log_files = os.getenv("LOG_FILES", "")
LOG_FILES = [os.path.expanduser(elem) for elem in log_files.split(",")]


def scan(
    logs: bool = False,
    proc: bool = False,
    cpu: bool = False,
    gpu: bool = False,
    dir: str = None,
    network: str = None,
    js: str = None,
    url: str = None,
    devmode: str = None,
    time: str = "24h",
) -> None:
    """
    Starts execution and contains the main logic of the program, scanning for various suspicious activities.

    Args:
        logs (bool): Whether to scan logs (default is False).
        proc (bool): Whether to scan running processes (default is False).
        cpu (bool): Whether to scan for suspicious CPU usage (default is False).
        gpu (bool): Whether to scan for suspicious GPU usage (default is False).
        dir (str, optional): Directory to scan logs from (default is None).
        network (str, optional): Network interface to scan (default is None).
        js (str, optional): JavaScript file to scan (default is None).
        url (str, optional): URL to scan (default is None).
        time (str): Time duration for logs scan (default is "24h").

    Returns:
        None
    """
    report_buffer = StringIO()

    if proc:
        processes_scan(report_buffer)

    if cpu:
        scan_cpu(report_buffer)

    if gpu:
        scan_gpu(report_buffer)

    if network:
        active_hosts = discover_active_hosts(network)
        if active_hosts:
            scan_hosts_for_miner_ports(active_hosts, report_buffer)
        else:
            print("No active hosts found.")

    if url:
        scan_url(url, report_buffer)

    if devmode:
        scan_url(devmode, report_buffer)

    if js:
        scan_js(js, report_buffer)

    if platform == "darwin":
        LOG_FILES.extend(
            [
                os.path.expanduser("~/Library/Logs/"),
                os.path.expanduser("/var/log/system.log"),
                os.path.expanduser("/var/log/install.log"),
                # os.path.expanduser("~/Library/LaunchAgents/"),
                # os.path.expanduser("~/Library/Application Support/"),
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
                os.path.expanduser("/var/log/syslog"),
            ],
        )

    if logs:
        if os.geteuid() != 0:
            print(
                "System wide logs '/var/log/system.log' for MacOS and '/var/log/syslog' for Linux could not be analyzed as current user is not root. Please re-run the script as root using 'sudo'."
            )
        else:
            logs_scan(LOG_FILES, report_buffer, time=time)

    if dir:
        if os.path.isdir(dir):
            logs_scan([dir], report_buffer, time=time)
        else:
            print(f"Provided logs directory {dir} is not a valid directory.")
            sys.exit(1)

    print("Scan complete.")
    print(f"Results are shown here: http://127.0.0.1:5555/")

    report_text = report_buffer.getvalue()
    send_report_to_server(report_text)
    report_buffer.close()
