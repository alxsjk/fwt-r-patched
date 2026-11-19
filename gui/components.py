#!/usr/bin/env python3
"""FWT Reborn - Reusable UI Components for Tkinter Desktop Application."""

from __future__ import annotations

import contextlib
import queue
import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from tkinter import messagebox
from typing import Optional

from gui.theme import (
    ACCENT_AMBER,
    ACCENT_BLUE,
    ACCENT_CYAN,
    ACCENT_GREEN,
    ACCENT_RED,
    BG_BORDER,
    BG_CARD,
    BG_CONSOLE,
    BG_INPUT,
    FONT_FAMILY,
    FONT_MONO,
    TEXT_CONSOLE,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
)


class StatusBadge(tk.Frame):
    """Pill badge indicating status (e.g. Active, Inactive, Clean, Custom)."""

    def __init__(self, parent: tk.Widget, text: str = "", active: bool = False, **kwargs):
        super().__init__(parent, bg=BG_CARD, **kwargs)
        self.label = tk.Label(
            self,
            text=f"  {text}  ",
            font=(FONT_FAMILY, 9, "bold"),
            padx=4,
            pady=2,
        )
        self.label.pack(padx=1, pady=1)
        self.set_status(text, active)

    def set_status(self, text: str, active: bool, color: Optional[str] = None):
        self.label.config(text=f"  {text}  ")
        if color:
            bg_c = color
            fg_c = "#ffffff"
        elif active:
            bg_c = "#064e3b"
            fg_c = "#34d399"
        else:
            bg_c = "#374151"
            fg_c = "#9ca3af"
        self.label.config(bg=bg_c, fg=fg_c)


class LogViewer(tk.Frame):
    """Monospace dark console viewer with color tags, auto-scroll and clipboard copy."""

    def __init__(self, parent: tk.Widget, **kwargs):
        super().__init__(parent, bg=BG_CARD, bd=1, relief="solid", **kwargs)

        # Header controls
        header = tk.Frame(self, bg=BG_CARD)
        header.pack(fill="x", padx=8, pady=4)

        lbl = tk.Label(
            header,
            text="Console & Patch Logs",
            font=(FONT_FAMILY, 10, "bold"),
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        lbl.pack(side="left")

        self.auto_scroll_var = tk.BooleanVar(value=True)
        chk = tk.Checkbutton(
            header,
            text="Auto-scroll",
            variable=self.auto_scroll_var,
            font=(FONT_FAMILY, 9),
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
            selectcolor=BG_INPUT,
            activebackground=BG_CARD,
            activeforeground=TEXT_PRIMARY,
        )
        chk.pack(side="right", padx=4)

        btn_copy = tk.Button(
            header,
            text="Copy Logs",
            command=self.copy_logs,
            font=(FONT_FAMILY, 8),
            bg=BG_INPUT,
            fg=TEXT_SECONDARY,
            activebackground=BG_BORDER,
            activeforeground=TEXT_PRIMARY,
            bd=0,
            padx=8,
            pady=2,
            cursor="hand2",
        )
        btn_copy.pack(side="right", padx=4)

        btn_clear = tk.Button(
            header,
            text="Clear",
            command=self.clear,
            font=(FONT_FAMILY, 8),
            bg=BG_INPUT,
            fg=TEXT_SECONDARY,
            activebackground=BG_BORDER,
            activeforeground=TEXT_PRIMARY,
            bd=0,
            padx=8,
            pady=2,
            cursor="hand2",
        )
        btn_clear.pack(side="right", padx=4)

        # Scrolled text area
        text_frame = tk.Frame(self, bg=BG_CONSOLE)
        text_frame.pack(fill="both", expand=True, padx=4, pady=4)

        self.text = tk.Text(
            text_frame,
            wrap="word",
            font=(FONT_MONO, 9),
            bg=BG_CONSOLE,
            fg=TEXT_CONSOLE,
            insertbackground=TEXT_PRIMARY,
            selectbackground=ACCENT_BLUE,
            selectforeground="#ffffff",
            bd=0,
            padx=8,
            pady=8,
            state="disabled",
        )
        self.scrollbar = tk.Scrollbar(text_frame, orient="vertical", command=self.text.yview)
        self.text.config(yscrollcommand=self.scrollbar.set)

        self.scrollbar.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)

        # Tags
        self.text.tag_config("info", foreground=ACCENT_CYAN)
        self.text.tag_config("success", foreground=ACCENT_GREEN)
        self.text.tag_config("warn", foreground=ACCENT_AMBER)
        self.text.tag_config("error", foreground=ACCENT_RED)
        self.text.tag_config("dim", foreground=TEXT_MUTED)
        self.text.tag_config("bold", font=(FONT_MONO, 9, "bold"))

        # Thread-safe log queue: worker threads only enqueue; all Tk calls
        # happen in _drain_queue() on the main thread.
        self._log_queue: queue.Queue[tuple[str, str]] = queue.Queue()
        self.after(50, self._drain_queue)

    def log(self, message: str, tag: str = "normal"):
        """Thread-safe: may be called from any thread."""
        self._log_queue.put((message, tag))

    def _drain_queue(self):
        processed = 0
        try:
            while processed < 200:
                try:
                    message, tag = self._log_queue.get_nowait()
                except queue.Empty:
                    break
                # A single bad line must not kill the log pump.
                with contextlib.suppress(Exception):
                    self._append_log(message, tag)
                processed += 1
        finally:
            with contextlib.suppress(tk.TclError):
                self.after(0 if processed >= 200 else 50, self._drain_queue)

    def _append_log(self, message: str, tag: str):
        self.text.config(state="normal")
        # Auto-tag based on content keywords if normal
        cur_tag = tag
        if cur_tag == "normal":
            low = message.lower()
            if "error" in low or "failed" in low or "exception" in low:
                cur_tag = "error"
            elif "success" in low or "complete" in low or "ready" in low:
                cur_tag = "success"
            elif "warn" in low:
                cur_tag = "warn"
            elif "reading" in low or "aligning" in low or "signing" in low or "applying" in low:
                cur_tag = "info"

        self.text.insert("end", message + "\n", cur_tag)
        # Keep memory bounded during long builds.
        if int(self.text.index("end-1c").split(".")[0]) > 20000:
            self.text.delete("1.0", "2000.0")
        if self.auto_scroll_var.get():
            self.text.see("end")
        self.text.config(state="disabled")

    def clear(self):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.config(state="disabled")

    def copy_logs(self):
        content = self.text.get("1.0", "end").strip()
        if content:
            self.clipboard_clear()
            self.clipboard_append(content)
            messagebox.showinfo("Copied", "Logs copied to clipboard!")


class FilePathPicker(tk.Frame):
    """File selector with entry and browse button."""

    def __init__(
        self,
        parent: tk.Widget,
        label: str,
        default_path: str = "",
        on_change: Optional[Callable[[str], None]] = None,
        file_types: Optional[list[tuple[str, str]]] = None,
        is_save: bool = False,
        **kwargs,
    ):
        super().__init__(parent, bg=BG_CARD, **kwargs)
        self.on_change = on_change
        self.file_types = file_types or [("All Files", "*.*")]
        self.is_save = is_save

        lbl = tk.Label(
            self,
            text=label,
            font=(FONT_FAMILY, 9, "bold"),
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
        )
        lbl.pack(anchor="w", padx=2, pady=2)

        row = tk.Frame(self, bg=BG_CARD)
        row.pack(fill="x", expand=True)

        self.var = tk.StringVar(value=default_path)
        self.entry = tk.Entry(
            row,
            textvariable=self.var,
            font=(FONT_MONO, 9),
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
            bd=1,
            relief="solid",
        )
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 6), ipady=4)
        self.var.trace_add("write", lambda *_: self._handle_change())

        btn = tk.Button(
            row,
            text="Browse...",
            command=self._browse,
            font=(FONT_FAMILY, 9),
            bg=BG_BORDER,
            fg=TEXT_PRIMARY,
            activebackground=BG_INPUT,
            activeforeground=TEXT_PRIMARY,
            bd=0,
            padx=10,
            pady=3,
            cursor="hand2",
        )
        btn.pack(side="right")

    def _handle_change(self):
        if self.on_change:
            self.on_change(self.var.get().strip())

    def _browse(self):
        from tkinter import filedialog
        current = self.var.get().strip()
        initial_path = Path(current) if current else None
        initialdir = str(initial_path.parent) if initial_path and initial_path.parent else None
        initialfile = initial_path.name if initial_path else None
        if self.is_save:
            path = filedialog.asksaveasfilename(
                title="Select Output APK",
                filetypes=self.file_types,
                initialdir=initialdir,
                initialfile=initialfile,
            )
            if path and not path.lower().endswith(".apk"):
                path += ".apk"
        else:
            path = filedialog.askopenfilename(
                title="Select Base APK",
                filetypes=self.file_types,
                initialdir=initialdir,
            )
        if path:
            self.var.set(path)

    def get_path(self) -> str:
        return self.var.get().strip()

