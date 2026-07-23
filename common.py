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
from datetime import datetime, time as dtime, timezone, timedelta

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

# Trusted-time sources (see the "Trusted time / anti-tamper" section). HTTPS
# hosts are queried for their TLS-authenticated Date header; NTP hosts are a
# faster, lower-trust fallback.
DEFAULT_TIME_SYNC_HOSTS = ["www.google.com", "www.cloudflare.com",
                           "www.microsoft.com"]
DEFAULT_NTP_HOSTS = ["pool.ntp.org", "time.windows.com", "time.google.com"]


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
        "timer_font_size": 9,          # 4 (tiny) .. 12 (large)
        "timer_opacity": 0.65,         # 0.0 (invisible) .. 1.0 (solid)
        "warn_minutes": 10,            # timer turns red under this many minutes left
        # Anti-clock-tampering. The window and daily limit are decided against a
        # UTC epoch shifted by this fixed offset (minutes east of UTC), pinned at
        # install, instead of the live OS time zone — so a child changing the
        # Windows time zone (a non-admin action) cannot move the window or roll
        # the day. None means "not pinned yet; fall back to the OS offset".
        "utc_offset_minutes": None,
        # Trusted-time sources queried by the service (LocalSystem, so it has
        # network access even when the child account is restricted). HTTPS Date
        # headers are TLS-validated and hard to spoof without admin; NTP is a
        # faster fallback used only when HTTPS is unreachable.
        "time_sync_hosts": DEFAULT_TIME_SYNC_HOSTS,
        "time_sync_ntp": DEFAULT_NTP_HOSTS,
        # How far the OS clock may disagree with trusted time before the session
        # is treated as tampered (seconds).
        "time_tamper_threshold_seconds": 90,
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
    return {
        "date": "", "used_seconds": 0, "override_until": 0.0,
        # Anti-tamper anchors (see the trusted-time section below).
        # High-water mark of the highest trusted epoch ever seen: a later OS
        # clock that is *below* this is a rollback.
        "max_trusted_epoch": 0.0,
        # Calendar date (pinned-offset local) that trusted time last confirmed.
        "last_trusted_date": "",
        # Last known-good trusted epoch, persisted to survive reboots.
        "trusted_anchor_epoch": 0.0,
    }


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
# Trusted time / anti-tamper
#
# The service decides the window and the daily reset against *trusted* time, not
# the raw OS clock, so a child cannot earn time by changing the date, the time,
# or (with no admin) the Windows time zone. See service.py for the loop that
# holds the anchor and applies these helpers.
# --------------------------------------------------------------------------- #
def current_utc_offset_minutes():
    """The OS's current local UTC offset in minutes east of UTC. Spoofable by a
    time-zone change, so only used to *pin* the offset at install (and as a
    fallback before a pin exists), never as a live authority."""
    off = datetime.now().astimezone().utcoffset()
    return int(off.total_seconds() // 60) if off else 0


def effective_offset_minutes(cfg):
    """The pinned offset if set, else the live OS offset (pre-pin fallback)."""
    off = cfg.get("utc_offset_minutes")
    if off is None:
        return current_utc_offset_minutes()
    return int(off)


def fmt_utc_offset(minutes):
    sign = "+" if minutes >= 0 else "-"
    m = abs(int(minutes))
    return f"UTC{sign}{m // 60:02d}:{m % 60:02d}"


def _local_dt_from_epoch(epoch, offset_minutes):
    return (datetime.fromtimestamp(epoch, tz=timezone.utc)
            + timedelta(minutes=offset_minutes))


def local_date_from_epoch(epoch, offset_minutes):
    """YYYY-MM-DD of a UTC epoch shifted by a fixed offset — the day identity,
    independent of the OS time zone."""
    return _local_dt_from_epoch(epoch, offset_minutes).strftime("%Y-%m-%d")


def local_time_from_epoch(epoch, offset_minutes):
    """Wall-clock time-of-day of a UTC epoch shifted by a fixed offset, for the
    window check — independent of the OS time zone."""
    return _local_dt_from_epoch(epoch, offset_minutes).time()


def detect_tamper(os_epoch, trusted_epoch, max_trusted_epoch, build_epoch,
                  have_anchor, threshold=90, rollback_skew=120,
                  forward_grace=30 * 3600):
    """Decide whether the OS clock should be distrusted. Pure — every input is
    supplied so it is fully unit-testable without touching the real clock.

    Returns (suspect: bool, reason: str). Reasons:
      before_build        OS clock predates the build (impossible).
      rollback            OS clock is below the trusted high-water mark.
      divergence          OS clock disagrees with a live trusted anchor.
      unconfirmed_forward offline, OS clock jumped implausibly far ahead of the
                          high-water mark with no anchor to confirm it.
    """
    if os_epoch < build_epoch - rollback_skew:
        return True, "before_build"
    if max_trusted_epoch and os_epoch < max_trusted_epoch - rollback_skew:
        return True, "rollback"
    if have_anchor and trusted_epoch is not None:
        if abs(os_epoch - trusted_epoch) > threshold:
            return True, "divergence"
        return False, ""
    # No live anchor (offline). Accept a plausible forward drift from the
    # high-water mark (a normal power-off), but flag a big unconfirmed jump.
    if max_trusted_epoch and os_epoch > max_trusted_epoch + forward_grace:
        return True, "unconfirmed_forward"
    return False, ""


class TimeAuthority:
    """Holds the trusted-time anchor and answers "what time is it really?".

    An anchor is a (trusted_epoch, monotonic) pair captured at a successful
    network sync. `trusted_now()` extrapolates it with `time.monotonic()`, which
    no clock change can move. With no anchor (e.g. offline since boot) it returns
    None and callers fall back to the OS clock, guarded by `detect_tamper`."""

    def __init__(self):
        self._anchor_epoch = None
        self._anchor_mono = None

    def set_anchor(self, trusted_epoch, mono=None):
        self._anchor_epoch = float(trusted_epoch)
        self._anchor_mono = time.monotonic() if mono is None else mono

    @property
    def have_anchor(self):
        return self._anchor_epoch is not None

    def trusted_now(self, mono=None):
        if self._anchor_epoch is None:
            return None
        m = time.monotonic() if mono is None else mono
        return self._anchor_epoch + (m - self._anchor_mono)


def fetch_https_epoch(hosts, timeout=6):
    """Median epoch from the TLS-validated Date header of several HTTPS hosts.
    Returns a float epoch, or None if none answered. Spoofing this requires a
    trusted certificate, which a non-admin user cannot install."""
    import ssl
    import http.client
    from email.utils import parsedate_to_datetime
    ctx = ssl.create_default_context()
    got = []
    for host in hosts:
        conn = None
        try:
            conn = http.client.HTTPSConnection(host, timeout=timeout, context=ctx)
            conn.request("HEAD", "/")
            resp = conn.getresponse()
            date = resp.getheader("Date")
            if date:
                got.append(parsedate_to_datetime(date).timestamp())
        except Exception:
            continue
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
    if not got:
        return None
    got.sort()
    return got[len(got) // 2]


def fetch_ntp_epoch(hosts, timeout=5):
    """Epoch from the first SNTP host that answers, or None. Unauthenticated, so
    lower trust than HTTPS — used only as a fallback."""
    import socket as _socket
    NTP_DELTA = 2208988800  # seconds between 1900-01-01 and 1970-01-01
    packet = b"\x1b" + 47 * b"\0"
    for host in hosts:
        s = None
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(packet, (host, 123))
            data, _ = s.recvfrom(48)
            if len(data) >= 44:
                secs = struct.unpack("!I", data[40:44])[0]
                return float(secs - NTP_DELTA)
        except Exception:
            continue
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
    return None


def fetch_trusted_epoch(cfg):
    """Best trusted epoch available: HTTPS (authenticated) first, then NTP.
    Returns (epoch, source) or (None, "")."""
    epoch = fetch_https_epoch(cfg.get("time_sync_hosts") or DEFAULT_TIME_SYNC_HOSTS)
    if epoch is not None:
        return epoch, "https"
    epoch = fetch_ntp_epoch(cfg.get("time_sync_ntp") or DEFAULT_NTP_HOSTS)
    if epoch is not None:
        return epoch, "ntp"
    return None, ""


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
