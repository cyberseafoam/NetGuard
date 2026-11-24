"""Bounded TCP connect scanner for local development."""
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor


def validate_target(target):
    address = ipaddress.ip_address(target.strip())
    if str(address) not in ('127.0.0.1', '::1'):
        raise ValueError('Active scans are restricted to 127.0.0.1 and ::1.')
    return str(address)


def scan_port(target, port, timeout=0.3):
    target = validate_target(target)
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('Invalid TCP port.')
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return {'port': port, 'status': 'Open'}
    except ConnectionRefusedError:
        return {'port': port, 'status': 'Closed'}
    except OSError:
        return {'port': port, 'status': 'Unknown'}


def scan_ports(target, ports):
    target = validate_target(target)
    ports = sorted(set(ports))
    if not ports or len(ports) > 256 or any(not isinstance(p, int) or not 1 <= p <= 65535 for p in ports):
        raise ValueError('Select 1–256 valid TCP ports.')
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda p: scan_port(target, p), ports))
    return results, round(time.monotonic() - start, 3)
