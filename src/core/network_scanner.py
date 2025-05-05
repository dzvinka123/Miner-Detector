import os
import nmap
from dotenv import load_dotenv

load_dotenv()

suspicious_keywords = os.getenv("SUSPICIOUS_KEYWORDS", "")
MINING_PORTS = os.getenv("MINNING_PORTS", "")
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


def discover_active_hosts(network: str) -> list:
    """
    Discover active hosts in the specified network using a ping scan.

    Args:
        network (str): The network address to scan for active hosts.

    Returns:
        list: A list of active host IPs.
    """
    nm = nmap.PortScanner()
    print(f"Scanning for active hosts in {network}...")

    nm.scan(hosts=network, arguments="-sn")  # Ping scan
    active_hosts = [host for host in nm.all_hosts() if nm[host].state() == "up"]
    return active_hosts


def scan_hosts_for_miner_ports(hosts: list) -> None:
    """
    Scan each host for open ports related to mining activity.

    Args:
        hosts (list): A list of host IPs to scan for mining-related ports.

    Returns:
        None
    """
    port_scanner = nmap.PortScanner()

    for host in hosts:
        print(f"Scanning {host} for mining ports ({MINING_PORTS})...")
        port_scanner.scan(hosts=host, arguments=f"-p {MINING_PORTS} --open")

        if host in port_scanner.all_hosts():
            for protocol in port_scanner[host].all_protocols():
                ports = port_scanner[host][protocol]
                for port in sorted(ports.keys()):
                    service_name = ports[port].get("name", "unknown")
                    print(
                        f"{host} has port {port}/{protocol} OPEN — Potential mining activity (Service: {service_name})"
                    )
        else:
            print(f"{host} has no potential mining activity.")
