import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NETBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    8080: "HTTP-ALT",
}

def get_service_name(port: int) -> str:
    """
    Retourne le service généralement associé à un port TCP.
    """
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]

    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "UNKNOWN"

def resolve_target(target: str) -> str:
    """
    Convertit un nom de domaine ou une adresse IP en adresse IPv4.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as error:
        raise ValueError(f"Impossible de résoudre la cible : {target}") from error


def scan_port(ip_address: str, port: int, timeout: float = 0.5) -> bool:
    """
    Tente une connexion TCP sur un port précis.

    Retourne True si le port est ouvert,
    sinon False.
    """
    if not 1 <= port <= 65535:
        raise ValueError("Le port doit être compris entre 1 et 65535.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.settimeout(timeout)

        result = client_socket.connect_ex((ip_address, port))

    return result == 0

def grab_banner(
    ip_address: str,
    port: int,
    timeout: float = 1.0,
) -> str | None:
    """
    Tente de récupérer la bannière d'un service TCP.

    Retourne une chaîne nettoyée si une bannière est reçue,
    sinon None.
    """
    if not 1 <= port <= 65535:
        raise ValueError("Le port doit être compris entre 1 et 65535.")

    try:
        with socket.create_connection(
            (ip_address, port),
            timeout=timeout,
        ) as client_socket:
            client_socket.settimeout(timeout)

            if port in {80, 8080, 8000, 8888}:
                request = (
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host: {ip_address}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                client_socket.sendall(request.encode("ascii"))

            banner = client_socket.recv(1024)

    except (OSError, TimeoutError):
        return None

    if not banner:
        return None

    decoded_banner = banner.decode(
        "utf-8",
        errors="replace",
    )

    cleaned_banner = " ".join(decoded_banner.split())

    return cleaned_banner[:200] or None

def scan_ports(
    ip_address: str,
    ports: list[int],
    timeout: float = 0.5,
    workers: int = 50,
) -> dict[int, bool]:
    """
    Scanne plusieurs ports TCP en parallèle.

    Args:
        ip_address: Adresse IP à scanner.
        ports: Liste des ports TCP.
        timeout: Temps maximal d'attente par port.
        workers: Nombre maximal de threads simultanés.

    Returns:
        Un dictionnaire associant chaque port à son état.
    """
    results: dict[int, bool] = {}

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {
            executor.submit(scan_port, ip_address, port, timeout): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]

            try:
                results[port] = future.result()
            except OSError:
                results[port] = False

    return dict(sorted(results.items()))