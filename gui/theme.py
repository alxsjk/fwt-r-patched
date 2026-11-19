#!/usr/bin/env python3
"""FWT Reborn - Modern Dark Theme Configuration."""

import os

IS_WINDOWS = (os.name == "nt")

# Font families
FONT_FAMILY = "Segoe UI" if IS_WINDOWS else "Ubuntu"
FONT_MONO = "Consolas" if IS_WINDOWS else "DejaVu Sans Mono"

# Palette
BG_MAIN = "#12141a"
BG_CARD = "#1a1d26"
BG_INPUT = "#0d0f14"
BG_BORDER = "#2b3040"
BG_CONSOLE = "#080a0e"

TEXT_PRIMARY = "#f3f4f6"
TEXT_SECONDARY = "#9ca3af"
TEXT_MUTED = "#6b7280"
TEXT_CONSOLE = "#d1d5db"

ACCENT_BLUE = "#3b82f6"
ACCENT_BLUE_HOVER = "#2563eb"
ACCENT_GREEN = "#10b981"
ACCENT_GREEN_HOVER = "#059669"
ACCENT_CYAN = "#06b6d4"
ACCENT_AMBER = "#f59e0b"
ACCENT_RED = "#ef4444"
ACCENT_PURPLE = "#8b5cf6"

# Card & Layout Constants
PAD_SM = 8
PAD_MD = 12
PAD_LG = 16

