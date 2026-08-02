import argparse

import pytest

from netscan.cli import parse_ports


def test_parse_single_ports() -> None:
    result = parse_ports("22,80,443")

    assert result == [22, 80, 443]


def test_parse_port_range() -> None:
    result = parse_ports("20-25")

    assert result == [20, 21, 22, 23, 24, 25]


def test_parse_mixed_ports_and_ranges() -> None:
    result = parse_ports("22,80,8000-8002")

    assert result == [22, 80, 8000, 8001, 8002]


def test_parse_ports_removes_duplicates() -> None:
    result = parse_ports("80,80,443,443")

    assert result == [80, 443]


def test_parse_ports_sorts_results() -> None:
    result = parse_ports("443,22,80")

    assert result == [22, 80, 443]


@pytest.mark.parametrize(
    "value",
    [
        "0",
        "65536",
        "70000",
        "-1",
    ],
)
def test_parse_ports_rejects_out_of_range_values(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        parse_ports(value)


@pytest.mark.parametrize(
    "value",
    [
        "abc",
        "80-abc",
        "100-20",
        "",
        "80,,443",
    ],
)
def test_parse_ports_rejects_invalid_formats(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        parse_ports(value)