from netscan.scanner import resolve_target, scan_port


target = input("Enter a target: ")
port = int(input("Enter a TCP port: "))

try:
    ip_address = resolve_target(target)
    is_open = scan_port(ip_address, port)

    print(f"Resolved IP address: {ip_address}")

    if is_open:
        print(f"Port {port} is OPEN")
    else:
        print(f"Port {port} is CLOSED or FILTERED")

except ValueError as error:
    print(error)