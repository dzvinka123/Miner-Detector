import os
import sys
import argparse

from sys import platform
from processes_logs_scanner import (
    scan_processes,
    user_accessible_scan,
    user_system_wide_scan,
    LOG_FILES,
    LOG_DIRS,
)


def ask_and_check_root():
    """
    To get or deny access for user.
    """
    response = input("System scan needs root access. Proceed? (y/n): ")
    if response.lower() == "y":
        if not os.geteuid() == 0:
            print("Please re-run the script as root using 'sudo'.")
            sys.exit(1)
        return True
    return False


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
    parser.add_argument("-d", "--dir", help="Directory to scan.")
    parser.add_argument(
        "-t",
        "--time",
        help="How long ago something has been done (e.g., 24h, 7d).",
        default="24h",
    )
    args = parser.parse_args()
    directory = args.dir
    time = args.time

    write_file = open(
        args.file, "a", encoding="utf8"
    )  # append (writes at the end, creates file if needed)
    if os.geteuid() != 0:
        root_access = ask_and_check_root()
    else:
        root_access = True

    scan_processes(write_file)

    if platform == "darwin":
        LOG_FILES.extend(
            [
                os.path.expanduser("~/Library/Logs/"),
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
            ],
        )

    if directory:
        if os.path.isdir(directory):
            LOG_FILES.append(directory)
        else:
            print(f"Provided directory {directory} is not a valid directory.")
            sys.exit(1)

    user_accessible_scan(write_file, time=time)

    if root_access:
        if platform == "darwin":
            LOG_DIRS.extend(
                [
                    os.path.expanduser("/var/log/system.log"),
                    os.path.expanduser("/var/log/install.log"),
                    os.path.expanduser("/tmp"),
                    # os.path.expanduser("/Library/LaunchAgents/"),
                    # os.path.expanduser("~/Library/LaunchDaemons/"),
                ],
            )
        elif platform == "linux":
            LOG_DIRS.extend(
                [
                    os.path.expanduser("/var/log/syslog"),
                    os.path.expanduser("/tmp"),
                    # os.path.expanduser("/var/log/messages"),
                    # os.path.expanduser("/var/log/auth.log"),
                    # os.path.expanduser("/var/log/kern.log"),
                ],
            )

        user_system_wide_scan(write_file, time=time)
    else:
        print(
            "System wide logs were not analyzed as current user is not root. Re-run with 'sudo'."
        )

    write_file.close()
    print(f"Results are written inside: {args.file}")
    print("Scan complete.")


if __name__ == "__main__":
    main()
