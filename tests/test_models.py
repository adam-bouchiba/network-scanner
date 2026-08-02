from dataclasses import FrozenInstanceError

import pytest

from netscan.models import ScanResult


def test_scan_result_exposes_open_status() -> None:
    result = ScanResult(
        port=443,
        is_open=True,
        service="HTTPS",
    )

    assert result.status == "open"


def test_scan_result_exposes_closed_status() -> None:
    result = ScanResult(
        port=22,
        is_open=False,
        service="SSH",
    )

    assert result.status == "closed"


def test_scan_result_uses_none_as_default_banner() -> None:
    result = ScanResult(
        port=80,
        is_open=True,
        service="HTTP",
    )

    assert result.banner is None


def test_scan_result_converts_to_dictionary() -> None:
    result = ScanResult(
        port=22,
        is_open=True,
        service="SSH",
        banner="SSH-2.0-OpenSSH_9.6",
    )

    assert result.to_dict() == {
        "port": 22,
        "service": "SSH",
        "banner": "SSH-2.0-OpenSSH_9.6",
        "status": "open",
    }


def test_scan_result_is_immutable() -> None:
    result = ScanResult(
        port=443,
        is_open=True,
        service="HTTPS",
    )

    with pytest.raises(FrozenInstanceError):
        result.port = 80