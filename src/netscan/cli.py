from netscan.scanner import resolve_target, scan_ports, get_service_name

COMMON_PORTS = list(range(1, 1001))


target = input("Enter a target: ")

try:
    ip_address = resolve_target(target)
    results = scan_ports(ip_address, COMMON_PORTS)

    print(f"\nScanning {target} ({ip_address})...\n")
    print(f"{'PORT':<10}{'STATUS':<12}{'SERVICE'}")
    print("-" * 32)

    open_ports_found = False

    for port, is_open in results.items():
        if is_open:
            open_ports_found = True
            service = get_service_name(port)
            print(f"{port:<10}{'OPEN':<12}{service}")

    if not open_ports_found:
        print("No open ports found.")

except ValueError as error:
    print(error)