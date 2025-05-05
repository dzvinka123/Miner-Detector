import os
import nmap
from dotenv import load_dotenv

load_dotenv()

suspicious_keywords = os.getenv("SUSPICIOUS_KEYWORDS", "")
MINING_PORTS = os.getenv("MINNING_PORTS", "")
SUSPICIOUS_KEYWORDS = suspicious_keywords.split(",") if suspicious_keywords else []


def is_suspicious(line):
    """
    Check whether given log has any suspicious keyword.
    """
    return any(keyword in line.lower() for keyword in SUSPICIOUS_KEYWORDS)


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
                    service_name = ports[port].get("name", "unknown")
                    print(
                        f"{host} has port {port}/{protocol} OPEN — Potential mining activity (Service: {service_name})"
                    )
        else:
            print(f"{host} has no potential mining activity.")
