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
    parser = argparse.ArgumentParser(description="CLI Dcanner for Miners Detection.")
    parser.add_argument("file_name", help="File to save results into.")
    args = parser.parse_args()

    write_file = open(args.file_name, "a", encoding="utf8")
    if os.geteuid() != 0:
        root_access = ask_and_check_root()
    else:
        root_access = True

    scan_processes(write_file)

    if platform == "darwin":
        LOG_FILES.extend(
            [
                os.path.expanduser("~/Library/Logs/"),
                # os.path.expanduser("~/Library/Application Support/"),
                os.path.expanduser("~/Library/LaunchAgents/"),
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

    user_accessible_scan(write_file)

    if root_access:
        if platform == "darwin":
            LOG_DIRS.extend(
                [
                    os.path.expanduser("/var/log/system.log"),
                    os.path.expanduser("/var/log/install.log"),
                    os.path.expanduser("/Library/LaunchAgents/"),
                    os.path.expanduser("~/Library/LaunchDaemons/"),
                ],
            )
        elif platform == "linux":
            LOG_DIRS.extend(
                [
                    os.path.expanduser("/var/log/syslog"),
                    os.path.expanduser("/var/log/messages"),
                    os.path.expanduser("/var/log/auth.log"),
                    os.path.expanduser("/var/log/kern.log"),
                ],
            )

        user_system_wide_scan(write_file)
    else:
        print(
            "System wide logs were not analyzed as current user is not root. Re-run with 'sudo'."
        )

    write_file.close()
    print(f"Results are written inside: {args.file_name}")
    print("Scan complete.")


if __name__ == "__main__":
    main()


# def main():
#     parser = argparse.ArgumentParser(description="Miner scanner CLI")
#     parser.add_argument("path", help="Path to file or directory")
#     args = parser.parse_args()

#     if os.path.isdir(args.path):
#         for root, _, files in os.walk(args.path):
#             for f in files:
#                 for result in scan_file(os.path.join(root, f)):
#                     print(f"[!] Suspicious: {result}")
#     else:
#         for result in scan_file(args.path):
#             print(f"[!] Suspicious: {result}")
