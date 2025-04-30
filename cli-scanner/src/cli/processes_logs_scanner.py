import os
import re
import time
import psutil
import GPUtil
import requests
import subprocess

from sys import platform
from os import access, R_OK
from dotenv import load_dotenv
from util import parse_time_threshold

import nmap


load_dotenv()

suspicious_keywords = os.getenv("SUSPICIOUS_KEYWORDS", "")
log_files = os.getenv("LOG_FILES", "")

MINING_PORTS = os.getenv("MINNING_PORTS")
SUSPICIOUS_KEYWORDS = suspicious_keywords.split(",") if suspicious_keywords else []
LOG_FILES = [os.path.expanduser(elem) for elem in log_files.split(",")]


def is_suspicious(line):
    """
    Check whether given log has any suspicious keyword.
    """
    return any(keyword in line.lower() for keyword in SUSPICIOUS_KEYWORDS)


def processes_scan(write_file):
    """
    Scanning processes for suspicious keywords.
    """
    print("Scanning processes...")
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            process_name = proc.info["name"].lower()
            process_exe = proc.info["exe"].lower()
            if is_suspicious(process_name) or is_suspicious(process_exe):
                write_file.write(
                    f"Process {proc.info['pid']}: {proc.info['name']}\n executable: {proc.info['exe']}\n CPU percentage: {proc.info['cpu_percent']}\n"
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


def scan_journalctl(write_file):
    """
    Scanning Journalctl on Linux systems.
    """
    print("Scanning Journalctl logs...")
    try:
        output = subprocess.check_output(
            ["journalctl", "--user", "-n", "1000"], stderr=subprocess.DEVNULL
        )
        for line in output.decode(errors="ignore").splitlines():
            if is_suspicious(line):
                write_file.write(f"[!] Suspicious Journalctl entry: {line}\n")
    except Exception as e:
        print(e)
        write_file.write(e)
        write_file.write("\n")


def scan_file(file_path, write_file, time_thresh="24h"):
    """
    Scanning files by given file path.
    """
    time_threshold_seconds = parse_time_threshold(time_thresh)  # convert to seconds
    last_time = time.time() - time_threshold_seconds
    if access(file_path, R_OK):
        if os.path.getmtime(file_path) > last_time:
            try:
                with open(file_path, "r", errors="ignore", encoding="utf8") as file:
                    for i, line in enumerate(file, 1):
                        if is_suspicious(line):
                            write_file.write(
                                f"[!] Suspicious entry in {file_path}:{i}: {line.strip()}\n"
                            )
            except Exception as e:
                print(e)
                print(f"[!] File failed openning {file_path}\n")
                write_file.write(f"[!] File failed openning {file_path}\n")

    else:
        print(f"[!] File does not have reading access  {file_path}\n")
        write_file.write(f"[!] File does not have reading access {file_path}\n")


def logs_scan(write_file, time):
    """
    Scanning user-accessible directories with cashes and etc.
    """
    print("Scanning logs and directories...")
    for path in LOG_FILES:
        if os.path.exists(path):
            if os.path.isfile(path):
                if os.path.getsize(path) < 10 * 1024 * 1024:  # 10MB
                    scan_file(path, write_file, time)
                else:
                    write_file.write(f"[!] Skipped {path} due to excessive size.\n")
            elif os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for f in files:
                        scan_file(os.path.join(root, f), write_file, time)
        else:
            print(f"[!] File does not exist {path}\n")
    if platform == "linux":
        scan_journalctl(write_file)


def scan_cpu(write_file):
    print("Scanning CPU...")
    write_file.write(f"CPU Usage: {psutil.cpu_percent(interval=1)}%\n")
    write_file.write(f"CPU Cores: {psutil.cpu_count(logical=False)}\n")
    write_file.write(f"Total CPU Threads: {psutil.cpu_count()}\n")


def scan_gpu(write_file):
    print("Scanning GPU...")
    gpus = GPUtil.getGPUs()
    for gpu in gpus:
        write_file.write(f"GPU: {gpu.name}\n")
        write_file.write(f"Load: {gpu.load*100:.1f}%\n")
        write_file.write(f"Memory Used: {gpu.memoryUsed}MB / {gpu.memoryTotal}MB\n")


def discover_active_hosts(network):
    """
    Function to discover active hosts in the network
    """

    nm = nmap.PortScanner()
    print(f"Scanning for active hosts in {network}...")

    nm.scan(hosts=network, arguments="-sn")  # Ping scan
    active_hosts = [host for host in nm.all_hosts() if nm[host].state() == "up"]
    return active_hosts


def scan_hosts_for_miner_ports(hosts):
    """
    Function to scan each host for mining-related ports
    """
    port_scanner = nmap.PortScanner()
    
    for host in hosts:
        print(f"Scanning {host} for mining ports ({MINING_PORTS})...")
        port_scanner.scan(hosts=host, arguments=f"-p {MINING_PORTS} --open")

        if host in port_scanner.all_hosts():
            for protocol in port_scanner[host].all_protocols():
                ports = port_scanner[host][protocol]
                for port in sorted(ports.keys()):
                    service_name = ports[port].get('name', 'unknown')
                    print(f"{host} has port {port}/{protocol} OPEN — Potential mining activity (Service: {service_name})")
        else:
            print(f"{host} has no potential mining activity.")


def scan_url(network_url, write_file):
    print("Scanning network URL...")
    response = requests.get(network_url, timeout=10)
    content = response.text.lower()

    if is_suspicious(content):
        # highlight all sus entries
        write_file.write(f"URL {network_url} is suspicious.\n")


def scan_js(js_file, write_file):
    with open(js_file, "r", encoding="utf-8") as file:
        content = file.read().lower()

    regex_patterns = [f'r"{elem}"' for elem in SUSPICIOUS_KEYWORDS]
    for pattern in regex_patterns:
        if re.search(pattern, content):
            write_file.write(f"JS content of file {js_file} is suspicious.\n")
