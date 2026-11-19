from __future__ import annotations

from core.apk_tooling import AdbHelper
from fwt_patcher import _resolve_device


class FakeAdb(AdbHelper):
    def __init__(self, devices):
        self._devices = devices

    def list_devices(self):
        return self._devices


def _device(dev_id: str, state: str = "device") -> dict[str, str]:
    return {"id": dev_id, "model": "Test", "state": state, "label": dev_id, "error": ""}


def test_single_ready_device_is_selected():
    dev, error = _resolve_device(FakeAdb([_device("emulator-5554")]), None)
    assert dev == "emulator-5554"
    assert error == ""


def test_multiple_ready_devices_require_explicit_choice():
    dev, error = _resolve_device(
        FakeAdb([_device("a"), _device("b")]), None
    )
    assert dev is None
    assert "--device" in error


def test_unknown_requested_device_is_rejected():
    dev, error = _resolve_device(FakeAdb([_device("a")]), "10.0.0.9:5555")
    assert dev is None
    assert "not found" in error


def test_unauthorized_device_is_not_used():
    dev, error = _resolve_device(FakeAdb([_device("a", "unauthorized")]), None)
    assert dev is None
    assert "unauthorized" in error


def test_dash_prefixed_device_id_is_rejected():
    dev, error = _resolve_device(FakeAdb([_device("a")]), "-e")
    assert dev is None
    assert "Invalid device id" in error
