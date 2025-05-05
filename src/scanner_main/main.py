import argparse

from services.cli import scan
from services.daemon import ScannerDaemon


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
        "--logs", action="store_true", help="Scan for suspicious log entries"
    )
    scan_parser.add_argument(
        "--dir", metavar="DIR", help="Scan logs in the given directory"
    )
    scan_parser.add_argument("--url", metavar="URL", help="Scan a specific URL")
    scan_parser.add_argument("--js", metavar="JS_FILE", help="Scan a JavaScript file")
    scan_parser.add_argument(
        "--time",
        help="How long ago something has been done (e.g., 24h, 7d).",
        default="24h",
    )

    # --- Daemon mode ---
    daemon_parser = subparsers.add_parser(
        "daemon", help="Run in background as a daemon"
    )
    daemon_parser.add_argument("--network", metavar="NET", help="Scan network activity")
    daemon_parser.add_argument(
        "--duration",
        type=int,
        help="Duration to run in seconds",
        default=300,
    )
    daemon_parser.add_argument(
        "--int",
        dest="interval",
        type=int,
        help="Interval between scans in seconds",
        default=30,
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if args.mode == "scan":
        scan(
            proc=args.proc,
            gpu=args.gpu,
            cpu=args.cpu,
            logs=args.logs,
            dir=args.dir,
            url=args.url,
            js=args.js,
            time=args.time,
        )
    elif args.mode == "daemon":
        daemon = ScannerDaemon(
            duration=args.duration, interval=args.interval, network=args.network
        )
        daemon.daemonize()
        daemon.run()


if __name__ == "__main__":
    main()
