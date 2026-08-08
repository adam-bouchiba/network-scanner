import socket
from unittest.mock import MagicMock, patch

import pytest

from netscan.scanner import (
    get_service_name,
    grab_banner,
    resolve_target,
    scan_port,
    scan_ports,
)


@patch("netscan.scanner.socket.create_connection")
def test_grab_banner_returns_received_banner(
    mock_create_connection: MagicMock,
) -> None:
    mock_socket = mock_create_connection.return_value.__enter__.return_value
    mock_socket.recv.return_value = b"SSH-2.0-OpenSSH_9.6\r\n"

    result = grab_banner(
        ip_address="127.0.0.1",
        port=22,
        timeout=1.0,
    )

    assert result == "SSH-2.0-OpenSSH_9.6"
    mock_socket.recv.assert_called_once_with(1024)


@patch("netscan.scanner.socket.create_connection")
def test_grab_banner_sends_http_head_request(
    mock_create_connection: MagicMock,
) -> None:
    mock_socket = mock_create_connection.return_value.__enter__.return_value
    mock_socket.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"

    result = grab_banner(
        ip_address="127.0.0.1",
        port=80,
    )

    assert result == "HTTP/1.1 200 OK Server: nginx"

    sent_request = mock_socket.sendall.call_args.args[0]

    assert b"HEAD / HTTP/1.1" in sent_request
    assert b"Connection: close" in sent_request


@patch("netscan.scanner.socket.create_connection")
def test_grab_banner_returns_none_on_connection_error(
    mock_create_connection: MagicMock,
) -> None:
    mock_create_connection.side_effect = OSError

    result = grab_banner(
        ip_address="127.0.0.1",
        port=22,
    )

    assert result is None


def test_get_service_name_for_known_port() -> None:
    assert get_service_name(80) == "HTTP"
    assert get_service_name(443) == "HTTPS"
    assert get_service_name(22) == "SSH"


@patch("netscan.scanner.socket.getservbyport")
def test_get_service_name_uses_system_lookup(
    mock_getservbyport: MagicMock,
) -> None:
    mock_getservbyport.return_value = "custom-service"

    result = get_service_name(9999)

    assert result == "CUSTOM-SERVICE"
    mock_getservbyport.assert_called_once_with(9999, "tcp")


@patch("netscan.scanner.socket.getservbyport")
def test_get_service_name_returns_unknown_when_lookup_fails(
    mock_getservbyport: MagicMock,
) -> None:
    mock_getservbyport.side_effect = OSError

    result = get_service_name(9999)

    assert result == "UNKNOWN"


def test_resolve_localhost() -> None:
    result = resolve_target("localhost")

    assert result == "127.0.0.1"


@patch("netscan.scanner.socket.gethostbyname")
def test_resolve_target_raises_value_error(
    mock_gethostbyname: MagicMock,
) -> None:
    mock_gethostbyname.side_effect = socket.gaierror

    with pytest.raises(ValueError, match="Impossible de résoudre la cible"):
        resolve_target("invalid-target")


@pytest.mark.parametrize("port", [0, -1, 65536, 70000])
def test_scan_port_rejects_invalid_ports(port: int) -> None:
    with pytest.raises(ValueError):
        scan_port("127.0.0.1", port)


@patch("netscan.scanner.socket.socket")
def test_scan_port_returns_true_when_connection_succeeds(
    mock_socket_class: MagicMock,
) -> None:
    mock_socket = mock_socket_class.return_value.__enter__.return_value
    mock_socket.connect_ex.return_value = 0

    result = scan_port("127.0.0.1", 80)

    assert result is True
    mock_socket.settimeout.assert_called_once_with(0.5)
    mock_socket.connect_ex.assert_called_once_with(("127.0.0.1", 80))


@patch("netscan.scanner.socket.socket")
def test_scan_port_returns_false_when_connection_fails(
    mock_socket_class: MagicMock,
) -> None:
    mock_socket = mock_socket_class.return_value.__enter__.return_value
    mock_socket.connect_ex.return_value = 111

    result = scan_port("127.0.0.1", 80)

    assert result is False


@patch("netscan.scanner.scan_port")
def test_scan_ports_returns_sorted_results(
    mock_scan_port: MagicMock,
) -> None:
    mock_scan_port.side_effect = lambda ip, port, timeout: port in {22, 443}

    results = scan_ports(
        ip_address="127.0.0.1",
        ports=[443, 80, 22],
        timeout=0.1,
        workers=2,
    )

    assert [result.port for result in results] == [
        22,
        80,
        443,
    ]

    assert [result.is_open for result in results] == [
        True,
        False,
        True,
    ]

    assert results[0].service == "SSH"
    assert results[1].service == "HTTP"
    assert results[2].service == "HTTPS"
