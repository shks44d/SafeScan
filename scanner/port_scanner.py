"""Fast TCP connect scanning and conservative service identification."""

from __future__ import annotations

import os
import re
import socket
import ssl
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed, wait

# Share a single native-thread budget; browser chunks are small enough for
# three overlapping requests to fit the serverless function time budget.
SCAN_THREADS = int(os.getenv("SAFESCAN_SCAN_THREADS", "160"))
MAX_ACTIVE_CHUNKS = int(os.getenv("SAFESCAN_MAX_ACTIVE_CHUNKS", "3"))
if SCAN_THREADS < 1 or MAX_ACTIVE_CHUNKS < 1:
    raise ValueError("Scan worker and active-chunk limits must be positive.")
_scan_slots = threading.BoundedSemaphore(MAX_ACTIVE_CHUNKS)
_pool_lock = threading.Lock()
_shared_pool: ThreadPoolExecutor | None = None
CONNECT_TIMEOUT = float(os.getenv("SAFESCAN_CONNECT_TIMEOUT", "0.8"))
BANNER_TIMEOUT = float(os.getenv("SAFESCAN_BANNER_TIMEOUT", "1.0"))
BANNER_LIMIT = 200

HTTP_PORTS = {
    80,
    81,
    443,
    3000,
    5000,
    7001,
    8000,
    8008,
    8080,
    8081,
    8088,
    8181,
    8443,
    8888,
    9000,
    9090,
    9200,
    9443,
    10000,
}
TLS_HTTP_PORTS = {443, 8443, 9443}
PORT_SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    1883: "mqtt",
    2049: "nfs",
    2375: "docker",
    2379: "etcd",
    3000: "http",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5672: "amqp",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-ssl",
    6379: "redis",
    6443: "kubernetes-api",
    8000: "http",
    8008: "http",
    8080: "http-proxy",
    8081: "http",
    8443: "https",
    8888: "http",
    9000: "http",
    9090: "http",
    9200: "elasticsearch",
    10250: "kubelet",
    11211: "memcached",
    15672: "rabbitmq-management",
    27017: "mongodb",
}

PRODUCT_PATTERNS = (
    (re.compile(r"OpenSSH[_/]([\w.p-]+)", re.IGNORECASE), "OpenSSH", "ssh"),
    (re.compile(r"nginx/([\w.-]+)", re.IGNORECASE), "nginx", "http"),
    (re.compile(r"Apache(?:/| httpd )([\w.-]+)", re.IGNORECASE), "Apache httpd", "http"),
    (re.compile(r"Microsoft-IIS/([\w.-]+)", re.IGNORECASE), "Microsoft IIS", "http"),
    (re.compile(r"lighttpd/([\w.-]+)", re.IGNORECASE), "lighttpd", "http"),
    (re.compile(r"Postfix", re.IGNORECASE), "Postfix", "smtp"),
    (re.compile(r"Exim(?:\s+|/)([\w.-]+)", re.IGNORECASE), "Exim", "smtp"),
    (re.compile(r"vsFTPd(?:\s+|/)([\w.-]+)", re.IGNORECASE), "vsftpd", "ftp"),
    (re.compile(r"ProFTPD(?:\s+|/)([\w.-]+)", re.IGNORECASE), "ProFTPD", "ftp"),
    (re.compile(r"Dovecot", re.IGNORECASE), "Dovecot", "imap"),
    (re.compile(r"Redis server v=([\w.-]+)", re.IGNORECASE), "Redis", "redis"),
)


def sanitize_banner(data: bytes | str) -> str:
    """Return a safe, compact banner excerpt."""
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    text = "".join(character if character.isprintable() else " " for character in text)
    return re.sub(r"\s+", " ", text).strip()[:BANNER_LIMIT]


def guessed_service(port: int) -> str:
    """Return a conventional service name for a port."""
    if port in PORT_SERVICES:
        return PORT_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def identify_service(
    port: int, banner: str, mysql_version: str | None = None
) -> dict[str, str | None]:
    """Prefer observed protocol evidence, then fall back to a port guess."""
    banner = banner[:4096]
    lowered = banner.lower()
    service: str | None = None
    product: str | None = None
    version: str | None = None
    if mysql_version:
        version = sanitize_banner(mysql_version)
        if "mariadb" in version.lower():
            product = "MariaDB"
            version = re.sub(r"^5\.5\.5-", "", version)
        else:
            product = "MySQL"
        service = "mysql"
    elif banner.startswith("SSH-"):
        service = "ssh"
    elif banner.startswith("HTTP/"):
        service = "https" if port in TLS_HTTP_PORTS else "http"
    elif banner.startswith("220"):
        if re.search(r"\b(?:smtp|esmtp|postfix|exim)\b", lowered):
            service = "smtp"
        elif re.search(r"\b(?:ftp|vsftpd|proftpd|filezilla)\b", lowered):
            service = "ftp"
        else:
            service = None
    elif banner.startswith("+OK") and (
        port in {110, 995} or "pop3" in lowered or "dovecot" in lowered
    ):
        service = "pop3"
    elif re.match(r"^\*\s+(OK|PREAUTH)", banner, re.IGNORECASE):
        service = "imap"
    elif banner.startswith("+PONG") or re.match(r"^-NOAUTH\b", banner, re.IGNORECASE):
        service, product = "redis", "Redis"

    product_source = banner
    if service in {"http", "https"}:
        header = re.search(r"^Server:[ \t]*([^\r\n]+)", banner, re.IGNORECASE | re.MULTILINE)
        product_source = header.group(1) if header else ""
    for pattern, detected_product, detected_service in PRODUCT_PATTERNS:
        if mysql_version:
            break
        match = pattern.search(product_source)
        if match:
            product = detected_product
            service = service or detected_service
            version = match.group(1) if match.lastindex else version
            break
    if service in {"http", "https"}:
        server = re.search(r"^Server:[ \t]*([^\r\n]+)", banner, re.IGNORECASE | re.MULTILINE)
        if server:
            value = server.group(1).strip()
            match = re.match(r"([^/\s]+)(?:/([^\s]+))?", value)
            if match:
                product = product or match.group(1)
                version = version or match.group(2)
    if not service:
        return {
            "service": guessed_service(port),
            "product": None,
            "version": None,
            "confidence": "port-guess",
        }
    return {
        "service": service,
        "product": sanitize_banner(product) if product else None,
        "version": sanitize_banner(version) if version else None,
        "confidence": "banner",
    }


def _address(ip: str, port: int) -> tuple:
    address = socket.getaddrinfo(ip, port, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST)[0]
    return address[0], address[4]


def _receive(sock: socket.socket, limit: int = 4096) -> bytes:
    sock.settimeout(BANNER_TIMEOUT)
    try:
        return sock.recv(limit)
    except (TimeoutError, OSError):
        return b""


def _probe_open_socket(sock: socket.socket, host: str, port: int) -> tuple[bytes, str | None]:
    initial = _receive(sock)
    mysql_version = None
    if initial and len(initial) > 5 and initial[4] == 10:
        mysql_version = initial[5:].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    if port == 6379 and not initial:
        sock.sendall(b"*1\r\n$4\r\nPING\r\n")
        initial = _receive(sock)
    if port in HTTP_PORTS:
        stream = sock
        if port in TLS_HTTP_PORTS:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                stream = context.wrap_socket(sock, server_hostname=host)
            except (OSError, ssl.SSLError):
                return initial, mysql_version
        authority = f"[{host}]" if ":" in host else host
        try:
            stream.sendall(
                f"HEAD / HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n".encode()
            )
            response = _receive(stream)
            initial = response or initial
        except OSError:
            pass
    return initial, mysql_version


def scan_port(ip: str, host: str, port: int) -> dict[str, object] | None:
    """Connect to one TCP port and return evidence only when it is open."""
    family, destination = _address(ip, port)
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(CONNECT_TIMEOUT)
        if sock.connect_ex(destination) != 0:
            return None
        data, mysql_version = _probe_open_socket(sock, host, port)
        banner = sanitize_banner(data)
        # Identify from the bounded original response so HTTP header boundaries
        # survive; normalize only the text presented to the browser afterward.
        identity = identify_service(port, data.decode("utf-8", errors="replace"), mysql_version)
        return {"port": port, "state": "open", "banner": banner, **identity}
    except OSError:
        return None
    finally:
        sock.close()


class ScanCapacityError(Exception):
    """The instance has no room for another scan chunk."""


class ScanQuotaError(Exception):
    """The caller has exhausted its port-work allowance."""


def _executor() -> ThreadPoolExecutor:
    """Lazily create one worker budget shared by every request in this process."""
    global _shared_pool
    with _pool_lock:
        if _shared_pool is None:
            _shared_pool = ThreadPoolExecutor(
                max_workers=SCAN_THREADS, thread_name_prefix="tcp-scan"
            )
        return _shared_pool


def _retire_executor(executor: ThreadPoolExecutor) -> None:
    """Drain even tasks hidden by a submit failure before permitting a new pool."""
    global _shared_pool
    with _pool_lock:
        # submit() enqueues before starting a thread. A failed Thread.start can
        # leave work without returning its Future, so drain the entire old pool.
        executor.shutdown(wait=True, cancel_futures=True)
        if _shared_pool is executor:
            _shared_pool = None


def scan_ports(
    ip: str, host: str, start: int, end: int, work_allowed: Callable[[], bool] | None = None
) -> list[dict[str, object]]:
    """Scan a chunk within the process-wide active-chunk and worker budgets."""
    if not 1 <= start <= end <= 65_535 or end - start + 1 > 2_000:
        raise ValueError("Invalid scan chunk range.")
    if not _scan_slots.acquire(blocking=False):
        raise ScanCapacityError("Scanner is busy. Please retry shortly.")
    futures = []
    results: list[dict[str, object]] = []
    try:
        if work_allowed is not None and not work_allowed():
            raise ScanQuotaError("Scan allowance reached. Please wait a minute and try again.")
        executor = _executor()
        for port in range(start, end + 1):
            try:
                future = executor.submit(scan_port, ip, host, port)
            except (RuntimeError, MemoryError):
                _retire_executor(executor)
                raise
            futures.append(future)
        for future in as_completed(futures):
            service = future.result()
            if service:
                results.append(service)
    finally:
        # Keep the admission slot until all submitted work has finished, including
        # partial submission failures. Otherwise errors could bypass the budget.
        for future in futures:
            future.cancel()
        wait([future for future in futures if not future.cancelled()])
        _scan_slots.release()
    return sorted(results, key=lambda item: int(item["port"]))
