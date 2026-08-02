import socket

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

def scan_ports(
    ip_address: str,
    ports: list[int],
    timeout: float = 0.5
) -> dict[int, bool]:
    """
    Scanne plusieurs ports TCP sur une adresse IP.

    Retourne un dictionnaire :
    {
        80: True,
        443: True,
        8080: False
    }
    """
    results = {}

    for port in ports:
        results[port] = scan_port(ip_address, port, timeout)

    return results