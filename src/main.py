import argparse

from cli.cli import scan
from servers.daemon_tool import ScannerDaemon


def parse_args():
    parser = argparse.ArgumentParser(description="Miner Detector CLI Tool")

    subparsers = parser.add_subparsers(
        dest="mode", required=True, help="Choose operation mode"
    )

    # --- Scan mode ---
    scan_parser = subparsers.add_parser("scan", help="Run immediate scan")

    scan_parser.add_argument(
        "--proc", action="store_true", help="Scan running processes"
    )
    scan_parser.add_argument(
        "--gpu", action="store_true", help="Scan for suspicious GPU usage"
    )
    scan_parser.add_argument(
        "--cpu", action="store_true", help="Scan for suspicious CPU usage"
    )
    scan_parser.add_argument(
        "--logs", metavar="LOG_DIR", help="Scan logs in the given directory"
    )
    scan_parser.add_argument(
        "-n", "--network", action="store_true", help="Scan network activity"
    )
    scan_parser.add_argument("--url", metavar="URL", help="Scan a specific URL")
    scan_parser.add_argument("--js", metavar="JS_FILE", help="Scan a JavaScript file")
    parser.add_argument(
        "-t",
        "--time",
        help="How long ago something has been done (e.g., 24h, 7d).",
        default="24h",
    )

    # --- Daemon mode ---
    daemon_parser = subparsers.add_parser(
        "daemon", help="Run in background as a daemon"
    )

    daemon_parser.add_argument(
        "--proc", action="store_true", help="Scan running processes"
    )
    daemon_parser.add_argument(
        "--gpu", action="store_true", help="Scan for suspicious GPU usage"
    )
    daemon_parser.add_argument(
        "--cpu", action="store_true", help="Scan for suspicious CPU usage"
    )
    daemon_parser.add_argument(
        "--logs", metavar="LOG_DIR", help="Scan logs in the given directory"
    )
    daemon_parser.add_argument(
        "-n", "--network", action="store_true", help="Scan network activity"
    )
    daemon_parser.add_argument(
        "--duration", type=int, required=True, help="Duration to run in seconds"
    )
    daemon_parser.add_argument(
        "--int",
        dest="interval",
        type=int,
        required=True,
        help="Interval between scans in seconds",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if args.mode == "scan":
        scan(args)
    elif args.mode == "daemon":
        daemon = ScannerDaemon(args)
        daemon.daemonize()
        daemon.run()


if __name__ == "__main__":
    main()
