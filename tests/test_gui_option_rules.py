"""GUI option rules: the limit-break pair must never be enabled together.

The window is built headless: ``tk.BooleanVar`` is replaced by a double that keeps the
same ``get``/``set``/``trace_add`` contract, so the exclusion callbacks in
``MainWindow._bind_option_exclusions`` run without a display.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from gui.main_window import MainWindow


class _FakeBoolVar:
    """Headless test double replicating tkinter.BooleanVar write traces."""

    def __init__(self, *, value: bool = False) -> None:
        self._value = bool(value)
        self._traces: list[Callable[[str, str, str], object]] = []

    def get(self) -> bool:
        return self._value

    def set(self, value: bool) -> None:
        self._value = bool(value)
        for callback in list(self._traces):
            callback("", "", "write")

    def trace_add(
        self, mode: str, callback: Callable[[str, str, str], object]
    ) -> str:
        assert mode == "write"
        self._traces.append(callback)
        return f"trace_{len(self._traces)}"


def _build_headless_option_window(monkeypatch: Any) -> MainWindow:
    monkeypatch.setattr("gui.main_window.tk.BooleanVar", _FakeBoolVar)
    window = MainWindow.__new__(MainWindow)
    window._init_option_vars()
    window._bind_option_exclusions()
    return window


def test_gui_default_limit_break_flags_do_not_conflict(monkeypatch) -> None:
    window = _build_headless_option_window(monkeypatch)
    active = [
        name
        for name, var in (
            ("cost_tenth", window.var_limit_break_cost_tenth),
            ("cost_fixed", window.var_limit_break_cost_fixed),
        )
        if var.get()
    ]
    assert active == ["cost_fixed"]


def test_gui_limit_break_options_are_mutually_exclusive(monkeypatch) -> None:
    window = _build_headless_option_window(monkeypatch)

    window.var_limit_break_cost_tenth.set(True)
    assert window.var_limit_break_cost_tenth.get() is True
    assert window.var_limit_break_cost_fixed.get() is False

    window.var_limit_break_cost_fixed.set(True)
    assert window.var_limit_break_cost_fixed.get() is True
    assert window.var_limit_break_cost_tenth.get() is False

    # Turning the active one off leaves both prices unselected; the CLI then
    # charges the stock price.
    window.var_limit_break_cost_fixed.set(False)
    assert window.var_limit_break_cost_fixed.get() is False
    assert window.var_limit_break_cost_tenth.get() is False
