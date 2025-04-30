import os
import sys
import argparse

from sys import platform
from processes_logs_scanner import (
    processes_scan,
    logs_scan,
    scan_cpu,
    scan_gpu,
    scan_network,
    scan_js,
    LOG_FILES,
)


def main():
    """
    Starts execution, contain main logic of program.
    """
    parser = argparse.ArgumentParser(
        description="CLI Scanner for Miners Detection.",
        epilog="Example usage: python scanner.py results.txt -d /home/user -t 24h",
    )
    parser.add_argument(
        "-f", "--file", help="File to save results into.", default="scan_results.txt"
    )
    parser.add_argument("--logs", help="Logs directory to scan.")
    parser.add_argument(
        "-t",
        "--time",
        help="How long ago something has been done (e.g., 24h, 7d).",
        default="24h",
    )
    parser.add_argument("--cpu", help="Flag to perform CPU scanning.")
    parser.add_argument("--gpu", help="Flag to perform GPU scanning.")
    parser.add_argument("--proc", help="Flag to perform processes scanning.")
    parser.add_argument("-n", "--network", help="Network URL to scan.")
    parser.add_argument("--js", help="JS file to scan.")

    args = parser.parse_args()
    logs = args.logs
    time = args.time
    cpu = args.cpu
    gpu = args.gpu
    proc = args.proc
    network = args.network
    js = args.js

    write_file = open(
        args.file, "a", encoding="utf8"
    )  # append (writes at the end, creates file if needed)

    if os.geteuid() != 0:
        print(
            "System wide logs '/var/log/system.log' for MacOS and '/var/log/syslog' for Linux could not be analyzed as current user is not root. Please re-run the script as root using 'sudo'."
        )
        sys.exit(1)

    if proc:
        processes_scan(write_file)

    if cpu:
        scan_cpu(write_file)

    if gpu:
        scan_gpu(write_file)

    if network:
        scan_network(network, write_file)

    if js:
        scan_js(js, write_file)

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

    logs_scan(write_file, time=time)

    write_file.close()
    print(f"Results are written inside: {args.file}")
    print("Scan complete.")


if __name__ == "__main__":
    main()
