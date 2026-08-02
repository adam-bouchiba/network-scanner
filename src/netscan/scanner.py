import socket


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