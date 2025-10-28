import re
import socket

from common_ports import ports_and_services


def get_open_ports(target: str, port_range, verbose=False):
    open_ports = []
    start = port_range[0]
    end = port_range[1]

    ports_to_scan = [i for i in range(start, end + 1)]

    target_type = "hostname"
    if re.search(r"^[\.0-9]+$", target):
        target_type = "IP address"
    try:
        host = socket.gethostbyname(target)
    except socket.gaierror:
        return "Error: Invalid " + target_type

    for port in ports_to_scan:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            rc = s.connect_ex((host, port))
            if rc == 0:
                open_ports.append(port)

    if verbose:
        try:
            hostname, _, _ = socket.gethostbyaddr(host)
        except socket.herror:
            hostname = None
        return pretty_print(hostname, host, open_ports)

    return open_ports


def pretty_print(hostname, ipaddress, open_ports):
    verbose = f"Open ports for "
    if hostname:
        verbose += f"{hostname} ({ipaddress})"
    else:
        verbose += ipaddress
    verbose += "\nPORT     SERVICE"  # 5 spaces
    for port in open_ports:
        verbose += f"\n{port:<9}{ports_and_services[port]}"  # 4 spaces
    return verbose

