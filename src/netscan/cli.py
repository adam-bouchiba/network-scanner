from netscan.scanner import resolve_target, scan_ports, get_service_name

COMMON_PORTS = [
    21,
    22,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    3306,
    3389,
    5432,
    8080,
]


target = input("Enter a target: ")

try:
    ip_address = resolve_target(target)
    results = scan_ports(ip_address, COMMON_PORTS)

    print(f"\nScanning {target} ({ip_address})...\n")
    print(f"{'PORT':<10}{'STATUS':<12}{'SERVICE'}")
    print("-" * 32)

    for port, is_open in results.items():
        status = "OPEN" if is_open else "CLOSED"
        service = get_service_name(port)
        print(f"{port:<10}{status:<12}{service}")

except ValueError as error:
    print(error)