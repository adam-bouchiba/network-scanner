import argparse
import sys
import time

from netscan.scanner import get_service_name, resolve_target, scan_ports


DEFAULT_PORTS = list(range(1, 1001))


def parse_ports(value: str) -> list[int]:
    """
    Convertit une expression de ports en liste triée.

    Formats acceptés :
    - 22,80,443
    - 1-1000
    - 22,80,8000-8100
    """
    ports: set[int] = set()

    for raw_part in value.split(","):
        part = raw_part.strip()

        if not part:
            raise argparse.ArgumentTypeError(
                "Une valeur de port est vide."
            )

        if "-" in part:
            try:
                start_text, end_text = part.split("-", maxsplit=1)
                start_port = int(start_text)
                end_port = int(end_text)
            except ValueError as error:
                raise argparse.ArgumentTypeError(
                    f"Plage de ports invalide : {part}"
                ) from error

            if start_port > end_port:
                raise argparse.ArgumentTypeError(
                    f"La plage doit être croissante : {part}"
                )

            ports.update(range(start_port, end_port + 1))

        else:
            try:
                ports.add(int(part))
            except ValueError as error:
                raise argparse.ArgumentTypeError(
                    f"Port invalide : {part}"
                ) from error

    if not ports:
        raise argparse.ArgumentTypeError(
            "Au moins un port doit être fourni."
        )

    if any(port < 1 or port > 65535 for port in ports):
        raise argparse.ArgumentTypeError(
            "Les ports doivent être compris entre 1 et 65535."
        )

    return sorted(ports)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscan",
        description="Fast multithreaded TCP port scanner written in Python.",
    )

    parser.add_argument(
        "target",
        help="Adresse IPv4 ou nom de domaine à scanner.",
    )

    parser.add_argument(
        "-p",
        "--ports",
        type=parse_ports,
        default=DEFAULT_PORTS,
        help="Ports à scanner. Exemples : 22,80,443 ou 1-1000.",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=0.5,
        help="Timeout par port en secondes. Défaut : 0.5.",
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=50,
        help="Nombre maximal de threads. Défaut : 50.",
    )

    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="Affiche aussi les ports fermés.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    arguments = parser.parse_args()

    if arguments.timeout <= 0:
        parser.error("--timeout doit être supérieur à zéro.")

    if arguments.workers <= 0:
        parser.error("--workers doit être supérieur à zéro.")

    try:
        ip_address = resolve_target(arguments.target)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(f"\nTarget:      {arguments.target}")
    print(f"Resolved IP: {ip_address}")
    print(f"Ports:       {len(arguments.ports)}")
    print(f"Workers:     {arguments.workers}")
    print("\nScanning...\n")

    started_at = time.perf_counter()

    try:
        results = scan_ports(
            ip_address=ip_address,
            ports=arguments.ports,
            timeout=arguments.timeout,
            workers=arguments.workers,
        )
    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
        return 130

    duration = time.perf_counter() - started_at
    open_ports = 0

    print(f"{'PORT':<10}{'STATUS':<12}{'SERVICE'}")
    print("-" * 34)

    for port, is_open in results.items():
        if not is_open and not arguments.show_closed:
            continue

        status = "OPEN" if is_open else "CLOSED"
        service = get_service_name(port)

        if is_open:
            open_ports += 1

        print(f"{port:<10}{status:<12}{service}")

    if open_ports == 0:
        print("No open ports found in the selected range.")

    print(
        f"\nScan completed in {duration:.2f}s "
        f"with {open_ports} open port(s)."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())