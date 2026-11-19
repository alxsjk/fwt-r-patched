from __future__ import annotations

import threading
from types import SimpleNamespace
from typing import Any

import pytest

from gui.main_window import MainWindow


class _DummyLogger:
    def __init__(self) -> None:
        self.entries: list[tuple[str, str]] = []

    def log(self, message: str, level: str = "info") -> None:
        self.entries.append((message, level))


def _make_close_stub(monkeypatch: pytest.MonkeyPatch) -> Any:
    window = MainWindow.__new__(MainWindow)
    window.is_busy = True
    window._close_requested = False
    window._cancel_event = threading.Event()
    window.log_viewer = _DummyLogger()  # type: ignore[assignment]
    window.btn_cancel = SimpleNamespace(config=lambda **kw: scheduled_cfg.append(kw))  # type: ignore[assignment]
    scheduled: list[tuple[int, Any]] = []
    scheduled_cfg: list[dict[str, Any]] = []
    destroyed = False

    def _destroy() -> None:
        nonlocal destroyed
        destroyed = True

    def _after(delay: int, callback: Any) -> str:
        scheduled.append((delay, callback))
        return "after_id"

    monkeypatch.setattr(window, "destroy", _destroy)
    monkeypatch.setattr(window, "after", _after)
    return window, scheduled, scheduled_cfg, lambda: destroyed


def test_on_close_while_idle_destroys_immediately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window, scheduled, _cfg, is_destroyed = _make_close_stub(monkeypatch)
    window.is_busy = False
    window._on_close()
    assert is_destroyed() is True
    assert scheduled == []


def test_on_close_during_build_prompts_once_and_polls_without_reprompting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window, scheduled, cfg, is_destroyed = _make_close_stub(monkeypatch)
    prompts: list[str] = []

    def _fake_askyesno(title: str, _msg: str, **_kw: Any) -> bool:
        prompts.append(title)
        return True

    monkeypatch.setattr("gui.main_window.messagebox.askyesno", _fake_askyesno)

    window._on_close()
    assert len(prompts) == 1
    assert window._cancel_event.is_set()
    assert window._close_requested is True
    assert cfg == [{"state": "disabled"}]
    assert len(window.log_viewer.entries) == 1
    assert len(scheduled) == 1

    # Clicking Close again while waiting must not prompt or log again.
    window._on_close()
    assert len(prompts) == 1
    assert len(window.log_viewer.entries) == 1

    # Polling while still busy re-schedules without re-opening askyesno or logging.
    _, poll_cb = scheduled.pop()
    poll_cb()
    assert len(prompts) == 1
    assert len(window.log_viewer.entries) == 1
    assert len(scheduled) == 1
    assert is_destroyed() is False

    # Once the worker clears is_busy, polling destroys the window.
    window.is_busy = False
    _, poll_cb = scheduled.pop()
    poll_cb()
    assert is_destroyed() is True


def test_on_close_cancelled_confirmation_leaves_build_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window, scheduled, _cfg, is_destroyed = _make_close_stub(monkeypatch)
    monkeypatch.setattr("gui.main_window.messagebox.askyesno", lambda *_a, **_kw: False)

    window._on_close()
    assert is_destroyed() is False
    assert not window._cancel_event.is_set()
    assert window._close_requested is False
    assert scheduled == []


def test_exit_menu_command_uses_on_close(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: dict[str, Any] = {}

    class _FakeMenu:
        def __init__(self, *_a: Any, **_kw: Any) -> None:
            pass

        def add_command(self, *, label: str, command: Any) -> None:
            commands[label] = command

        def add_separator(self) -> None:
            pass

        def add_cascade(self, **_kw: Any) -> None:
            pass

    monkeypatch.setattr("gui.main_window.tk.Menu", _FakeMenu)
    window = MainWindow.__new__(MainWindow)
    monkeypatch.setattr(window, "config", lambda **_kw: None)
    window._build_menu()
    assert commands["Exit"] == window._on_close


def test_on_close_during_device_op_waits_until_idle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window, scheduled, _cfg, is_destroyed = _make_close_stub(monkeypatch)
    window.is_busy = False
    window.device_op_active = True
    prompts: list[str] = []

    def _fake_askyesno(title: str, _msg: str, **_kw: Any) -> bool:
        prompts.append(title)
        return True

    monkeypatch.setattr("gui.main_window.messagebox.askyesno", _fake_askyesno)

    window._on_close()
    assert prompts == ["Device operation in progress"]
    assert not window._cancel_event.is_set()
    assert window._close_requested is True
    assert is_destroyed() is False
    assert len(scheduled) == 1

    _, poll_cb = scheduled.pop()
    poll_cb()
    assert is_destroyed() is False
    assert len(scheduled) == 1

    window.device_op_active = False
    _, poll_cb = scheduled.pop()
    poll_cb()
    assert is_destroyed() is True
