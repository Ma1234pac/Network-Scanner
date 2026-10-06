```python
#!/usr/bin/env python3

"""
Network Scanner
===============

A small educational network scanner with two modes:

1. Host Discovery
   - Checks which hosts are reachable in a subnet.

2. TCP Port Scanner
   - Checks selected TCP ports on a specific host.

Use this tool only on systems and networks that you own
or have explicit permission to test.
"""

import argparse
import ipaddress
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# ============================================================
# Configuration
# ============================================================

DEFAULT_TIMEOUT = 0.5
DEFAULT_WORKERS = 50

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
}


# ============================================================
# Utility Functions
# ============================================================

def print_banner():
    """Display application banner."""

    print()
    print("=" * 55)
    print("                 NETWORK SCANNER")
    print("=" * 55)
    print()


def validate_ip(ip):
    """Validate an IPv4 address."""

    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid IP address: {ip}"
        )


def validate_network(network):
    """Validate an IPv4 network."""

    try:
        return ipaddress.ip_network(network, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid network: {network}"
        )


# ============================================================
# VERSION 1 — HOST DISCOVERY
# ============================================================

def check_host(ip, timeout=DEFAULT_TIMEOUT):
    """
    Check whether a host accepts a TCP connection
    on a small set of common ports.

    Returns:
        dict containing host information.
    """

    common_ports = [22, 80, 443, 445, 3389]

    for port in common_ports:

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)

                result = sock.connect_ex((str(ip), port))

                if result == 0:
                    return {
                        "ip": str(ip),
                        "status": "ONLINE"
                    }

        except (socket.timeout, OSError):
            continue

    return {
        "ip": str(ip),
        "status": "OFFLINE"
    }


def discover_hosts(network, timeout=DEFAULT_TIMEOUT, workers=DEFAULT_WORKERS):
    """
    Discover reachable hosts inside a network.
    """

    hosts = list(network.hosts())

    print(f"[*] Network: {network}")
    print(f"[*] Hosts to check: {len(hosts)}")
    print()

    results = []

    with ThreadPoolExecutor(max_workers=workers) as executor:

        futures = {
            executor.submit(check_host, host, timeout): host
            for host in hosts
        }

        for future in as_completed(futures):

            result = future.result()
            results.append(result)

            if result["status"] == "ONLINE":
                print(
                    f"[+] {result['ip']:<15} "
                    f"{result['status']}"
                )

    results.sort(
        key=lambda item: ipaddress.ip_address(item["ip"])
    )

    print()
    print(f"[+] Online hosts: "
          f"{sum(r['status'] == 'ONLINE' for r in results)}")

    return results


# ============================================================
# VERSION 2 — TCP PORT SCANNER
# ============================================================

def scan_port(host, port, timeout=DEFAULT_TIMEOUT):
    """
    Check whether a TCP port is open.

    Returns:
        Port number and status.
    """

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

            sock.settimeout(timeout)

            result = sock.connect_ex((host, port))

            if result == 0:
                return {
                    "port": port,
                    "status": "OPEN",
                    "service": COMMON_PORTS.get(port, "Unknown")
                }

    except (socket.timeout, OSError):
        pass

    return {
        "port": port,
        "status": "CLOSED",
        "service": COMMON_PORTS.get(port, "Unknown")
    }


def scan_ports(
    host,
    ports,
    timeout=DEFAULT_TIMEOUT,
    workers=DEFAULT_WORKERS
):
    """
    Scan TCP ports on a single host.
    """

    print(f"[*] Target: {host}")
    print(f"[*] Ports: {ports}")
    print()

    results = []

    with ThreadPoolExecutor(max_workers=workers) as executor:

        futures = {
            executor.submit(
                scan_port,
                host,
                port,
                timeout
            ): port
            for port in ports
        }

        for future in as_completed(futures):

            result = future.result()
            results.append(result)

            if result["status"] == "OPEN":

                service = result["service"]

                print(
                    f"[+] Port {result['port']:<5} "
                    f"OPEN    {service}"
                )

    results.sort(key=lambda item: item["port"])

    open_ports = [
        result
        for result in results
        if result["status"] == "OPEN"
    ]

    print()
    print(f"[+] Open ports: {len(open_ports)}")

    return results


# ============================================================
# JSON EXPORT
# ============================================================

def save_json(data, filename):
    """
    Save scan results to a JSON file.
    """

    output = {
        "timestamp": datetime.now().isoformat(),
        "results": data
    }

    with open(filename, "w", encoding="utf-8") as file:

        json.dump(
            output,
            file,
            indent=4
        )

    print()
    print(f"[+] Results saved to: {filename}")


# ============================================================
# ARGUMENT PARSER
# ============================================================

def create_parser():

    parser = argparse.ArgumentParser(
        description="Educational Python Network Scanner"
    )

    subparsers = parser.add_subparsers(
        dest="mode",
        required=True
    )

    # --------------------------------------------------------
    # DISCOVERY MODE
    # --------------------------------------------------------

    discovery_parser = subparsers.add_parser(
        "discover",
        help="Discover online hosts"
    )

    discovery_parser.add_argument(
        "network",
        type=validate_network,
        help="Network in CIDR notation (example: 192.168.1.0/24)"
    )

    discovery_parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Connection timeout in seconds"
    )

    discovery_parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Number of concurrent workers"
    )

    discovery_parser.add_argument(
        "--output",
        help="Save results to JSON file"
    )

    # --------------------------------------------------------
    # PORT SCAN MODE
    # --------------------------------------------------------

    port_parser = subparsers.add_parser(
        "ports",
        help="Scan TCP ports on a host"
    )

    port_parser.add_argument(
        "host",
        type=validate_ip,
        help="Target IPv4 address"
    )

    port_parser.add_argument(
        "--ports",
        default="common",
        help=(
            "Ports to scan. "
            "Use 'common', a single port, "
            "or a range such as 20-100"
        )
    )

    port_parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Connection timeout in seconds"
    )

    port_parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Number of concurrent workers"
    )

    port_parser.add_argument(
        "--output",
        help="Save results to JSON file"
    )

    return parser


# ============================================================
# PORT PARSER
# ============================================================

def parse_ports(port_argument):
    """
    Convert user port input into a list of integers.

    Examples:

        common
        80
        22,80,443
        20-100
    """

    if port_argument.lower() == "common":

        return list(COMMON_PORTS.keys())

    ports = set()

    for part in port_argument.split(","):

        part = part.strip()

        if "-" in part:

            start, end = part.split("-", 1)

            start = int(start)
            end = int(end)

            if start > end:
                raise ValueError(
                    "Invalid port range."
                )

            for port in range(start, end + 1):

                if 1 <= port <= 65535:
                    ports.add(port)

        else:

            port = int(part)

            if 1 <= port <= 65535:
                ports.add(port)

    if not ports:
        raise ValueError("No valid ports specified.")

    return sorted(ports)


# ============================================================
# MAIN
# ============================================================

def main():

    print_banner()

    parser = create_parser()
    args = parser.parse_args()

    try:

        # ----------------------------------------------------
        # HOST DISCOVERY
        # ----------------------------------------------------

        if args.mode == "discover":

            results = discover_hosts(
                args.network,
                args.timeout,
                args.workers
            )

            if args.output:
                save_json(
                    results,
                    args.output
                )

        # ----------------------------------------------------
        # PORT SCANNING
        # ----------------------------------------------------

        elif args.mode == "ports":

            ports = parse_ports(args.ports)

            results = scan_ports(
                str(args.host),
                ports,
                args.timeout,
                args.workers
            )

            if args.output:
                save_json(
                    results,
                    args.output
                )

    except KeyboardInterrupt:

        print()
        print("[!] Scan interrupted by user.")

    except ValueError as error:

        print()
        print(f"[!] Error: {error}")


if __name__ == "__main__":
    main()
```
