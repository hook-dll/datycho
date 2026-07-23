"""
Central place for all names and install locations.

Internal identifiers (service id, folders, exe) are ASCII "datycho" for maximum
portability; everything the user sees uses the display name "datychö".
"""

import os

# Internal, ASCII-only identifiers.
APP_ID = "datycho"
SERVICE_NAME = "datycho"

# User-facing display name (may contain non-ASCII).
APP_DISPLAY = "datychö"
SERVICE_DISPLAY = "datychö"
SERVICE_DESCRIPTION = (
    "Enforces screen-time window and daily limit for chosen accounts; blocks "
    "the screen when out of time."
)
PUBLISHER = "datychö"
VERSION = "1.2.0"

# Absolute "past floor" for anti-tamper: any clock earlier than this is
# impossible (the software did not exist yet), so it is treated as tampered.
# Bump this on each release to at/just-before build time. 2026-07-01 00:00 UTC.
BUILD_EPOCH = 1782864000

# Locations.
PROGRAMDATA = os.environ.get("ProgramData", r"C:\ProgramData")
PROGRAMFILES = os.environ.get("ProgramFiles", r"C:\Program Files")

DATA_DIR = os.path.join(PROGRAMDATA, APP_ID)          # config, state, logs
INSTALL_DIR = os.path.join(PROGRAMFILES, APP_ID)      # program files
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
STATE_PATH = os.path.join(DATA_DIR, "state.json")
LOG_DIR = os.path.join(DATA_DIR, "logs")

# Windows "Add or remove programs" registry key.
UNINSTALL_KEY = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\\" + APP_ID
)

# Start-menu folder (all users).
START_MENU_DIR = os.path.join(
    PROGRAMDATA, r"Microsoft\Windows\Start Menu\Programs", APP_DISPLAY
)
