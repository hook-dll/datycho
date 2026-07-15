"""
Shared helpers for KidControlPc: paths, config, state, password hashing,
Windows session/lock detection, time-window math and logging.

This module is imported by both the SYSTEM service (service.py) and the
user-session GUI agent (agent.py).
"""

import os
import json
import time
import hmac
import base64
import struct
import hashlib
import logging
import logging.handlers
import ctypes
from ctypes import wintypes
from datetime import datetime, time as dtime

import branding

# All persistent data lives under C:\ProgramData\datycho so it is written by the
# SYSTEM service and readable by the kid's account, but not casually editable by
# a non-admin child.
DATA_DIR = branding.DATA_DIR
CONFIG_PATH = branding.CONFIG_PATH
STATE_PATH = branding.STATE_PATH
LOG_DIR = branding.LOG_DIR

# Directory containing this source tree (service.py / agent.py live here too).
APP_DIR = os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------- #
# Directories & logging
# --------------------------------------------------------------------------- #
def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)


def setup_logger(name):
    ensure_dirs()
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(
        os.path.join(LOG_DIR, f"{name}.log"),
        maxBytes=512 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    )
    logger.addHandler(handler)
    return logger


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def default_config():
    return {
        # Daily allowed clock window (24h HH:MM). May wrap past midnight.
        "window_start": "10:00",
        "window_end": "21:00",
        # Windows account names (no domain) the rules apply to. Empty list means
        # every account on the PC is enforced. List the kid's account here to
        # leave other accounts (e.g. a parent's) completely unrestricted.
        "enforced_users": [],
        # Daily usage cap in minutes.
        "daily_limit_minutes": 120,
        # How long a correct parent password unlocks for (minutes).
        # Set very high (e.g. 1440) to effectively grant the rest of the day.
        "override_grant_minutes": 60,
        # Local IPC between service and GUI agent.
        "ipc_port": 47615,
        "ipc_token": "",          # random, set at install
        # Base32 TOTP secret; overrides require a rotating 6-digit code from an
        # authenticator app rather than a static password, so a code the child
        # sees or guesses is useless within ~30–60 seconds.
        "totp_secret": "",
        # How the service launches the GUI agent in the user session. For the
        # packaged build this is the installed datycho.exe; for running from
        # source it is pythonw.exe plus the entry script. Set at install time.
        "app_exe": "",          # frozen datycho.exe (packaged build)
        "python_exe": "",       # pythonw.exe (source build)
        "entry_script": "",     # datycho.py (source build)
        # UI
        "timer_corner": "top-right",   # top/bottom + right/left/center
        "timer_opacity": 0.65,         # 0.3 (faint) .. 1.0 (solid)
        "warn_minutes": 10,            # timer turns red under this many minutes left
    }


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    # Merge in any keys added by newer versions.
    merged = default_config()
    merged.update(cfg)
    return merged


def save_config(cfg):
    ensure_dirs()
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG_PATH)


# --------------------------------------------------------------------------- #
# Daily state (usage + active override)
# --------------------------------------------------------------------------- #
def default_state():
    return {"date": "", "used_seconds": 0, "override_until": 0.0}


def load_state():
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            s = json.load(f)
        d = default_state()
        d.update(s)
        return d
    except (OSError, ValueError):
        return default_state()


def save_state(state):
    ensure_dirs()
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, STATE_PATH)


# --------------------------------------------------------------------------- #
# TOTP (RFC 6238 / RFC 4226) — compatible with Google Authenticator, Authy,
# Microsoft Authenticator, etc. SHA1, 6 digits, 30-second period.
# Implemented locally so there are no extra dependencies.
# --------------------------------------------------------------------------- #
TOTP_PERIOD = 30
TOTP_DIGITS = 6


def generate_totp_secret(nbytes=20):
    """Return a new random base32 secret (no padding), for provisioning an
    authenticator app."""
    return base64.b32encode(os.urandom(nbytes)).decode("ascii").rstrip("=")


def _b32decode(secret):
    secret = secret.strip().replace(" ", "").upper()
    pad = "=" * ((8 - len(secret) % 8) % 8)
    return base64.b32decode(secret + pad, casefold=True)


def _hotp(key, counter, digits=TOTP_DIGITS):
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    bincode = (
        (h[offset] & 0x7F) << 24
        | (h[offset + 1] & 0xFF) << 16
        | (h[offset + 2] & 0xFF) << 8
        | (h[offset + 3] & 0xFF)
    )
    return str(bincode % (10 ** digits)).zfill(digits)


def totp_now(secret, ts=None, period=TOTP_PERIOD, digits=TOTP_DIGITS):
    """Current code for a secret (used to confirm setup during install)."""
    if ts is None:
        ts = time.time()
    return _hotp(_b32decode(secret), int(ts // period), digits)


def verify_totp(secret, code, window=1, ts=None,
                period=TOTP_PERIOD, digits=TOTP_DIGITS):
    """Verify a code, allowing +/- `window` steps (default one 30s step) to
    absorb clock skew and the delay in typing it."""
    if not secret or not code:
        return False
    code = str(code).strip().replace(" ", "")
    if not code.isdigit() or len(code) != digits:
        return False
    if ts is None:
        ts = time.time()
    key = _b32decode(secret)
    counter = int(ts // period)
    for w in range(-window, window + 1):
        if hmac.compare_digest(_hotp(key, counter + w, digits), code):
            return True
    return False


def totp_uri(secret, account="parent", issuer=None):
    """otpauth:// provisioning URI; paste into any QR generator to scan, or add
    the raw secret manually in the authenticator app."""
    from urllib.parse import quote
    if issuer is None:
        issuer = branding.APP_DISPLAY
    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret}"
            f"&issuer={quote(issuer)}&period={TOTP_PERIOD}&digits={TOTP_DIGITS}")


# --------------------------------------------------------------------------- #
# Time-window math
# --------------------------------------------------------------------------- #
def parse_hhmm(text):
    h, m = text.strip().split(":")
    return dtime(int(h), int(m))


def in_window(now_time, start, end):
    """True if now_time falls inside [start, end], supporting windows that
    wrap past midnight (e.g. 22:00 -> 06:00)."""
    if start == end:
        return True  # full-day window
    if start < end:
        return start <= now_time <= end
    # wraps midnight
    return now_time >= start or now_time <= end


def fmt_hms(seconds):
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m}:{s:02d}"


# --------------------------------------------------------------------------- #
# Windows session / lock detection (ctypes)
# --------------------------------------------------------------------------- #
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)

_kernel32.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD

_wtsapi32.WTSQuerySessionInformationW.restype = wintypes.BOOL
_wtsapi32.WTSQuerySessionInformationW.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.c_int,
    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD),
]
_wtsapi32.WTSFreeMemory.argtypes = [ctypes.c_void_p]

_NO_SESSION = 0xFFFFFFFF
_WTS_CURRENT_SERVER = 0
_WTSUserName = 5


def get_active_console_session():
    """Session id of the physical console user, or None if none."""
    sid = _kernel32.WTSGetActiveConsoleSessionId()
    if sid == _NO_SESSION:
        return None
    return int(sid)


def list_local_users():
    """Return a sorted list of local, non-hidden Windows account names.

    Uses NetUserEnum via win32net so it works in a frozen exe without shelling
    out. Names may contain Cyrillic (or any Unicode) characters — they come back
    as proper Python strings. Filters out disabled accounts and the built-in
    service accounts a parent would never pick.
    """
    import win32net
    import win32netcon

    SKIP = {"administrator", "guest", "defaultaccount", "wdagutilityaccount",
            "krbtgt"}
    names = []
    resume = 0
    while True:
        data, _total, resume = win32net.NetUserEnum(
            None, 1, win32netcon.FILTER_NORMAL_ACCOUNT, resume)
        for u in data:
            name = u["name"]
            flags = u.get("flags", 0)
            if name.lower() in SKIP:
                continue
            if flags & win32netcon.UF_ACCOUNTDISABLE:
                continue
            names.append(name)
        if not resume:
            break
    # De-dupe while preserving case, sort case-insensitively.
    seen, out = set(), []
    for n in names:
        if n.lower() not in seen:
            seen.add(n.lower())
            out.append(n)
    return sorted(out, key=str.lower)


def get_session_username(session_id):
    """The account name logged into a session (no domain), or None if no user
    is logged in (e.g. at the login screen)."""
    buf = ctypes.c_void_p()
    nbytes = wintypes.DWORD()
    ok = _wtsapi32.WTSQuerySessionInformationW(
        _WTS_CURRENT_SERVER, session_id, _WTSUserName,
        ctypes.byref(buf), ctypes.byref(nbytes),
    )
    if not ok or not buf.value:
        return None
    try:
        name = ctypes.wstring_at(buf)
    finally:
        _wtsapi32.WTSFreeMemory(buf)
    return name or None


def today_str():
    return datetime.now().strftime("%Y-%m-%d")
