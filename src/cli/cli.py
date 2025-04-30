import os
import sys
import argparse
from io import StringIO

from sys import platform
from cli.processes_logs_scanner import (
    processes_scan,
    logs_scan,
    scan_cpu,
    scan_gpu,
    scan_hosts_for_miner_ports,
    discover_active_hosts,
    scan_url,
    scan_js,
    LOG_FILES,
)

from cli.util import send_report_to_server

def main():
    """
    Starts execution, contain main logic of program.
    """
    parser = argparse.ArgumentParser(
        description="CLI Scanner for Miners Detection.",
        epilog="Example usage: python scanner.py results.txt -d /home/user -t 24h",
    )
    parser.add_argument("--logs", help="Logs directory to scan.")
    parser.add_argument(
        "-t",
        "--time",
        help="How long ago something has been done (e.g., 24h, 7d).",
        default="24h",
    )
    parser.add_argument(
        "--cpu", action="store_true", help="Flag to perform CPU scanning."
    )
    parser.add_argument(
        "--gpu", action="store_true", help="Flag to perform GPU scanning."
    )
    parser.add_argument(
        "--proc", action="store_true", help="Flag to perform processes scanning."
    )
    parser.add_argument("-n", "--network", help="Flag to perform network scanning.")
    parser.add_argument("--url", help="URL to scan.")
    parser.add_argument("--js", help="JS file to scan.")

    args = parser.parse_args()
    logs = args.logs
    time = args.time
    cpu = args.cpu
    gpu = args.gpu
    proc = args.proc
    network = args.network
    url = args.url
    js = args.js

    report_buffer = StringIO()

    if os.geteuid() != 0:
        print(
            "System wide logs '/var/log/system.log' for MacOS and '/var/log/syslog' for Linux could not be analyzed as current user is not root. Please re-run the script as root using 'sudo'."
        )
        sys.exit(1)

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
        if os.path.isdir(logs):
            LOG_FILES.append(logs)
        else:
            print(f"Provided logs directory {logs} is not a valid directory.")
            sys.exit(1)

    logs_scan(report_buffer, time=time)
    print(f"Results are shown: web server name")
    print("Scan complete.")

    report_text = report_buffer.getvalue()
    send_report_to_server(report_text)
    report_buffer.close()

if __name__ == "__main__":
    main()
