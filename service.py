"""
datychö Windows service (runs as LocalSystem).

Responsibilities:
  * Authoritative usage tracking and enforcement (window + daily limit) for the
    accounts listed in config; other accounts are untouched.
  * Detects the console session lock state; time spent locked is NOT counted.
  * Serves status to the GUI agent over a localhost socket and processes
    authenticator-code override requests.
  * Supervises the GUI agent: launches it into the active user session and
    relaunches it within ~1s if the child kills it in Task Manager.
"""

import os
import sys
import json
import time
import socket
import threading

import common
import branding

import servicemanager  # noqa: E402
import win32serviceutil  # noqa: E402
import win32service  # noqa: E402
import win32event  # noqa: E402
import win32ts  # noqa: E402
import win32security  # noqa: E402
import win32process  # noqa: E402
import win32profile  # noqa: E402
import win32con  # noqa: E402
import win32api  # noqa: E402

log = common.setup_logger("service")

TICK_SECONDS = 1
PERSIST_EVERY = 15          # seconds between routine state writes
CONFIG_RELOAD_EVERY = 10    # ticks between config reloads

# Trusted-time sync cadence and tamper thresholds (seconds).
SYNC_INTERVAL = 600         # routine re-sync of the trusted anchor
SYNC_RETRY = 60             # faster retry while we have no anchor / after a drift
DRIFT_TRIGGER = 90          # unexplained OS-clock jump between ticks -> re-sync
RECHECK_GRACE = 25          # give a triggered re-sync this long before blocking

# Marker argument the SCM uses to launch this exe in service mode.
SERVICE_RUN_ARG = "--service-run"

# WTS session-change event codes (not exposed as pywin32 constants). Delivered
# via SERVICE_CONTROL_SESSIONCHANGE. WTS_SESSION_LOCK fires the instant Win+L is
# pressed — before the lock screen even switches to the credential desktop — so
# it reliably covers the whole locked period, unlike inspecting the desktop.
_WTS_SESSION_LOGON = 0x5
_WTS_SESSION_LOGOFF = 0x6
_WTS_SESSION_LOCK = 0x7
_WTS_SESSION_UNLOCK = 0x8


class DatychoService(win32serviceutil.ServiceFramework):
    _svc_name_ = branding.SERVICE_NAME
    _svc_display_name_ = branding.SERVICE_DISPLAY
    _svc_description_ = branding.SERVICE_DESCRIPTION

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = False

        self.lock = threading.Lock()
        self.cfg = common.default_config()
        self.state = common.default_state()
        # Latest computed snapshot the IPC server hands to the agent.
        self.status = {
            "blocked": False, "reason": "starting", "remaining": 0,
            "used": 0, "limit": 0, "override": False,
            "window": "", "warn_minutes": 10, "message": "",
        }

        # Supervised agent process handle + the session it was launched into.
        self.agent_handle = None
        self.agent_session = None

        # Workstation lock state, driven by SCM session-change events
        # (WTS_SESSION_LOCK/UNLOCK). Time while locked is not counted.
        self.session_locked = False

        # Trusted-time authority + the background sync thread's wake event.
        # The whole enforcement path decides against trusted time, not the raw
        # OS clock, so clock/date/time-zone changes can never grant free time.
        self.time_auth = common.TimeAuthority()
        # Manual-reset event: set to make the sync thread re-fetch immediately.
        self._resync_event = win32event.CreateEvent(None, 1, 0, None)
        self._last_os_epoch = None      # OS clock at the previous tick
        self._last_mono = None          # monotonic clock at the previous tick
        self._recheck_until = 0.0       # monotonic deadline suppressing a
        #                                 divergence block while a re-sync runs

    # ----- service control ------------------------------------------------- #
    def GetAcceptedControls(self):
        # Also receive lock/unlock (and logon/logoff) session notifications.
        return (super().GetAcceptedControls()
                | win32service.SERVICE_ACCEPT_SESSIONCHANGE)

    def SvcOtherEx(self, control, event_type, data):
        if control == win32service.SERVICE_CONTROL_SESSIONCHANGE:
            if event_type == _WTS_SESSION_LOCK:
                self.session_locked = True
                log.info("Session locked — afk time will not count")
            elif event_type in (_WTS_SESSION_UNLOCK, _WTS_SESSION_LOGON):
                self.session_locked = False
                log.info("Session unlocked")
            return
        return super().SvcOtherEx(control, event_type, data)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        try:
            self.main()
        except Exception:
            log.exception("Fatal error in service main loop")
            raise

    # ----- core loop ------------------------------------------------------- #
    def main(self):
        common.ensure_dirs()
        self._reload_config()
        self.state = common.load_state()
        # The day-roll is now trusted-time gated and happens inside the tick
        # loop; no OS-clock reset at startup (that was the exploitable path).

        self.running = True

        ipc_thread = threading.Thread(target=self._ipc_server, daemon=True)
        ipc_thread.start()

        # Trusted-time sync runs in its own thread so a fetch (which may block on
        # the network) never stalls enforcement.
        sync_thread = threading.Thread(target=self._time_sync_loop, daemon=True)
        sync_thread.start()

        # Keeping the agent alive runs in its own thread so it can wake the
        # instant the agent process exits (rather than on the 1s tick) and
        # relaunch with near-zero downtime.
        supervisor = threading.Thread(target=self._supervisor_loop, daemon=True)
        supervisor.start()

        log.info("Service started; window=%s limit=%smin",
                 self.status.get("window"), self.cfg.get("daily_limit_minutes"))

        last_persist = time.monotonic()
        last_blocked = None
        tick = 0

        while self.running:
            if tick % CONFIG_RELOAD_EVERY == 0:
                self._reload_config()
            tick += 1

            self._compute_tick()

            now = time.monotonic()
            blocked = self.status["blocked"]
            if blocked != last_blocked or (now - last_persist) >= PERSIST_EVERY:
                self._persist()
                last_persist = now
                last_blocked = blocked

            # Sleep until next tick or stop signal.
            if win32event.WaitForSingleObject(
                    self.stop_event, TICK_SECONDS * 1000) == win32event.WAIT_OBJECT_0:
                break

        self._persist()
        log.info("Service stopped")

    def _reload_config(self):
        try:
            cfg = common.load_config()
            with self.lock:
                self.cfg = cfg
        except (OSError, ValueError) as e:
            log.warning("Could not load config (%s); using defaults", e)

    def _maybe_roll_day(self, eff_epoch, offset, suspect, have_anchor, os_epoch):
        """Reset the daily counter when a genuine new day begins — gated on
        trusted time so a clock/date change can never trigger a free reset.

        * suspect clock -> never roll (fail-closed; the counter stays frozen).
        * trusted anchor present -> the trusted date is authoritative.
        * offline -> only a *forward* date change is honoured, and only within
          the plausible power-off window vetted by detect_tamper; the confirmed
          `last_trusted_date` is left untouched so the next sync re-checks it.
        """
        if suspect:
            return
        state = self.state
        eff_date = common.local_date_from_epoch(eff_epoch, offset)
        cur = state.get("date", "")
        if eff_date == cur:
            return
        if have_anchor or not cur or eff_date > cur:
            state["date"] = eff_date
            state["used_seconds"] = 0
            state["override_until"] = 0.0
            state["max_trusted_epoch"] = max(
                float(state.get("max_trusted_epoch", 0)), eff_epoch, os_epoch)
            if have_anchor:
                state["last_trusted_date"] = eff_date
                state["trusted_anchor_epoch"] = eff_epoch

    def _compute_tick(self):
        with self.lock:
            cfg = dict(self.cfg)
            state = self.state

        os_epoch = time.time()
        mono = time.monotonic()
        offset = common.effective_offset_minutes(cfg)

        # Trusted time is authoritative; fall back to the OS clock only when we
        # have no anchor (offline since boot), guarded by detect_tamper below.
        trusted = self.time_auth.trusted_now(mono)
        have_anchor = self.time_auth.have_anchor
        eff_epoch = trusted if (have_anchor and trusted is not None) else os_epoch

        # An unexplained OS-clock jump between ticks (live date/time change *or* a
        # wake-from-sleep) triggers an immediate re-sync; a divergence block is
        # held off briefly so the fresh anchor can settle before we judge.
        if self._last_os_epoch is not None and self._last_mono is not None:
            expected = self._last_os_epoch + (mono - self._last_mono)
            if abs(os_epoch - expected) > DRIFT_TRIGGER:
                self._request_resync(mono)
        self._last_os_epoch = os_epoch
        self._last_mono = mono

        max_trusted = float(state.get("max_trusted_epoch", 0))
        suspect, suspect_reason = common.detect_tamper(
            os_epoch, trusted, max_trusted, branding.BUILD_EPOCH, have_anchor,
            threshold=int(cfg.get("time_tamper_threshold_seconds", 90)))
        if suspect_reason == "divergence" and self._recheck_until and \
                mono < self._recheck_until:
            suspect, suspect_reason = False, ""  # let the pending re-sync settle

        # Advance the persisted high-water mark / anchor from trusted time.
        if have_anchor and trusted is not None and not suspect:
            state["max_trusted_epoch"] = max(max_trusted, trusted)
            state["trusted_anchor_epoch"] = trusted
            state["last_trusted_date"] = common.local_date_from_epoch(
                trusted, offset)

        self._maybe_roll_day(eff_epoch, offset, suspect, have_anchor, os_epoch)

        try:
            start = common.parse_hhmm(cfg["window_start"])
            end = common.parse_hhmm(cfg["window_end"])
        except Exception:
            start = common.parse_hhmm("00:00")
            end = common.parse_hhmm("23:59")

        limit = int(cfg["daily_limit_minutes"]) * 60
        used = int(state["used_seconds"])
        override_until = float(state.get("override_until", 0))
        override_active = eff_epoch < override_until
        override_remaining = int(max(0, override_until - eff_epoch)) \
            if override_active else 0

        sid = common.get_active_console_session()
        session_active = sid is not None
        current_user = common.get_session_username(sid) if session_active else None

        # Which accounts are enforced. Empty list => every account.
        enforced = [u.lower() for u in cfg.get("enforced_users", []) if u]
        monitored = (not enforced) or (
            current_user is not None and current_user.lower() in enforced)

        # Lock state comes from OS session-change events (see SvcOtherEx). Time
        # spent locked (Win+L, afk) is not counted.
        is_locked = self.session_locked

        within = common.in_window(
            common.local_time_from_epoch(eff_epoch, offset), start, end)
        remaining = max(0, limit - used)

        if not monitored:
            # This account isn't subject to the rules (e.g. a parent's login).
            allowed, reason = True, "unmonitored"
            message = ""
        elif suspect:
            # Fail-closed: the clock can't be trusted, so block rather than let a
            # date/time change buy free time. A parent code clears it, and it
            # clears itself once trusted time confirms the clock.
            allowed, reason = False, "time_suspect"
            message = ("The clock looks wrong or was changed. Ask a parent for "
                       "a code. This clears once the time is confirmed online.")
        elif override_active:
            allowed, reason = True, "override"
            message = "Parent override active"
        elif not within:
            allowed, reason = False, "outside_window"
            message = (f"Computer time is {cfg['window_start']}"
                       f"–{cfg['window_end']}. Come back later.")
        elif remaining <= 0:
            allowed, reason = False, "limit_reached"
            message = "Today's screen time is used up. Ask a parent for more."
        else:
            allowed, reason = True, "ok"
            message = ""

        # Count a second of usage only while a monitored account is actively
        # using an unlocked screen within the rules (reason == "ok"); never
        # during an override (bonus time) or for an unmonitored account.
        if reason == "ok" and session_active and not is_locked:
            used += TICK_SECONDS
            state["used_seconds"] = used
            remaining = max(0, limit - used)

        # Overlay visibility is deliberately independent of the lock state: the
        # block overlay stays shown even while the workstation is locked, so on
        # unlock it is already covering the desktop and there is no brief usable
        # gap. Time is still not counted while locked (see the counting guard
        # above), so a voluntary Win+L remains free time.
        show_block = session_active and monitored and not allowed
        # "blocked" = actively blocked on a live (unlocked) desktop. Drives the
        # lock-on-agent-death backstop and the persist-on-change trigger.
        blocked = show_block and not is_locked

        with self.lock:
            self.status = {
                "blocked": blocked,
                "show_block": show_block,
                "reason": reason,
                "monitored": monitored,
                "remaining": int(remaining),
                "used": int(used),
                "limit": int(limit),
                "override": override_active and monitored,
                "override_remaining": override_remaining,
                "time_suspect": bool(suspect),
                "suspect_reason": suspect_reason,
                "window": f"{cfg['window_start']}–{cfg['window_end']}",
                "warn_minutes": int(cfg.get("warn_minutes", 10)),
                "timer_corner": cfg.get("timer_corner", "top-right"),
                "timer_font_size": int(cfg.get("timer_font_size", 9)),
                "timer_opacity": float(cfg.get("timer_opacity", 0.65)),
                "message": message,
            }

    def _persist(self):
        try:
            common.save_state(self.state)
        except OSError as e:
            log.warning("Could not persist state: %s", e)

    # ----- parent override ------------------------------------------------- #
    def _grant_override(self, code):
        with self.lock:
            cfg = dict(self.cfg)
        secret = cfg.get("totp_secret")
        os_epoch = time.time()
        trusted = self.time_auth.trusted_now()
        # The parent's authenticator uses real time. Accept a match against the
        # OS clock (correct when untampered) OR trusted time (correct via the
        # monotonic anchor when the OS clock has been changed) — so a parent can
        # always clear a tamper block regardless of which clock is off.
        ok = common.verify_totp(secret, code, ts=os_epoch)
        if not ok and trusted is not None:
            ok = common.verify_totp(secret, code, ts=trusted)
        if not ok:
            log.info("Override attempt with incorrect/expired code")
            return False
        grant = int(cfg.get("override_grant_minutes", 60)) * 60
        # Anchor the expiry to the same time base the tick uses (trusted when
        # available) so a clock change can neither extend nor cut it short.
        base = trusted if trusted is not None else os_epoch
        self.state["override_until"] = base + grant
        self._persist()
        log.info("Parent override granted for %s minutes",
                 cfg.get("override_grant_minutes"))
        return True

    def _relock(self):
        """End any active override immediately (parent 'lock now')."""
        self.state["override_until"] = 0.0
        self._persist()
        log.info("Override ended by parent (re-lock)")

    # ----- trusted-time sync ---------------------------------------------- #
    def _request_resync(self, mono=None):
        """Ask the sync thread to re-fetch trusted time now, and suppress a
        divergence block for a short grace so the fresh anchor can settle."""
        if mono is None:
            mono = time.monotonic()
        self._recheck_until = mono + RECHECK_GRACE
        win32event.SetEvent(self._resync_event)

    def _time_sync_loop(self):
        """Periodically anchor trusted time from the network (see common.
        fetch_trusted_epoch). Runs as LocalSystem, so it reaches the network even
        when the child account is restricted. Sleeps on the stop event and a
        resync event, so it also fires immediately on a detected clock jump."""
        STOP = win32event.WAIT_OBJECT_0
        while self.running:
            with self.lock:
                cfg = dict(self.cfg)
            try:
                epoch, src = common.fetch_trusted_epoch(cfg)
            except Exception:
                log.exception("Trusted-time fetch crashed")
                epoch, src = None, ""

            if epoch is not None:
                self.time_auth.set_anchor(epoch)
                with self.lock:
                    self.state["trusted_anchor_epoch"] = epoch
                    self.state["max_trusted_epoch"] = max(
                        float(self.state.get("max_trusted_epoch", 0)), epoch)
                self._recheck_until = 0.0
                log.info("Trusted time synced via %s", src)
                wait_ms = SYNC_INTERVAL * 1000
            else:
                log.warning("Trusted-time sync failed (offline?); "
                            "using offline anti-tamper heuristics")
                wait_ms = SYNC_RETRY * 1000

            rc = win32event.WaitForMultipleObjects(
                [self.stop_event, self._resync_event], False, wait_ms)
            if rc == STOP:
                break
            # Woken by a resync request: clear it and loop to fetch immediately.
            win32event.ResetEvent(self._resync_event)

    # ----- IPC server ------------------------------------------------------ #
    def _ipc_server(self):
        with self.lock:
            port = int(self.cfg.get("ipc_port", 47615))
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("127.0.0.1", port))
            srv.listen(8)
        except OSError as e:
            log.error("Could not bind IPC socket on port %s: %s", port, e)
            return
        srv.settimeout(1.0)
        log.info("IPC listening on 127.0.0.1:%s", port)

        while self.running or not self.stop_event:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                if win32event.WaitForSingleObject(self.stop_event, 0) == \
                        win32event.WAIT_OBJECT_0:
                    break
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_conn, args=(conn,),
                             daemon=True).start()
        srv.close()

    def _handle_conn(self, conn):
        try:
            conn.settimeout(5.0)
            data = b""
            while b"\n" not in data and len(data) < 4096:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                data += chunk
            line = data.split(b"\n", 1)[0].decode("utf-8", "replace")
            req = json.loads(line) if line.strip() else {}
            resp = self._dispatch(req)
            conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
        except Exception as e:
            log.debug("IPC connection error: %s", e)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _dispatch(self, req):
        with self.lock:
            token = self.cfg.get("ipc_token", "")
        if req.get("token") != token:
            return {"ok": False, "error": "unauthorized"}

        cmd = req.get("cmd")
        if cmd == "status":
            with self.lock:
                return {"ok": True, **self.status}
        if cmd == "override":
            ok = self._grant_override(req.get("code", req.get("password", "")))
            return {"ok": ok, "error": "" if ok else "incorrect or expired code"}
        if cmd == "relock":
            self._relock()
            return {"ok": True}
        return {"ok": False, "error": "unknown command"}

    # ----- agent supervision ---------------------------------------------- #
    def _agent_alive(self):
        if self.agent_handle is None:
            return False
        try:
            code = win32process.GetExitCodeProcess(self.agent_handle)
            return code == win32con.STILL_ACTIVE
        except Exception:
            return False

    def _blocked_now(self):
        """True when a monitored account is actively blocked on a live (unlocked)
        desktop — i.e. killing the agent right now would expose a usable screen."""
        with self.lock:
            return bool(self.status.get("blocked"))

    def _supervisor_loop(self):
        """Keep the GUI agent alive in the active console session with near-zero
        downtime.

        Waits on the agent's process handle, so a kill in Task Manager is
        detected the instant it happens (not on the 1s tick) and the agent is
        relaunched immediately. If the agent dies while the account is actively
        blocked, the workstation is locked first, so the child lands on the
        secure Windows lock screen instead of the briefly-usable desktop that
        the old poll-based respawn left exposed.
        """
        STOP = win32event.WAIT_OBJECT_0
        while self.running:
            sid = common.get_active_console_session()
            if sid is None:
                # No interactive user (login screen); nothing to supervise.
                self._close_agent_handle()
                if win32event.WaitForSingleObject(self.stop_event, 1000) == STOP:
                    break
                continue

            if not self._agent_alive() or self.agent_session != sid:
                # Dead, never started, or the console session changed (fast user
                # switch / re-logon) -> (re)launch into the current session.
                self._close_agent_handle()
                self._launch_agent(sid)

            if self.agent_handle is None:
                # Launch failed; back off briefly before retrying.
                if win32event.WaitForSingleObject(self.stop_event, 1000) == STOP:
                    break
                continue

            # Wake on: stop requested, the agent process exiting, or 1s elapsing
            # (so a console-session change is still noticed promptly).
            rc = win32event.WaitForMultipleObjects(
                [self.stop_event, self.agent_handle], False, 1000)
            if rc == STOP:
                break
            if rc == STOP + 1:
                # Agent exited (killed in Task Manager or crashed). If it went
                # down while blocked, lock the screen before relaunching.
                if self._blocked_now():
                    self._lock_session(sid)
                self._close_agent_handle()
                # Loop re-runs immediately and relaunches the agent.

    def _agent_alive(self):
        if self.agent_handle is None:
            return False
        try:
            code = win32process.GetExitCodeProcess(self.agent_handle)
            return code == win32con.STILL_ACTIVE
        except Exception:
            return False

    def _close_agent_handle(self):
        if self.agent_handle is not None:
            try:
                win32api.CloseHandle(self.agent_handle)
            except Exception:
                pass
            self.agent_handle = None
            self.agent_session = None

    def _app_command(self, cfg, tail):
        """Command line that runs the app with `tail` (e.g. 'agent ...' or
        'lock'), for either the packaged (frozen exe) or from-source layout."""
        app_exe = cfg.get("app_exe") or ""
        if app_exe and os.path.isfile(app_exe):
            return f'"{app_exe}" {tail}'
        python_exe = cfg.get("python_exe") or ""
        entry = cfg.get("entry_script") or ""
        if python_exe and entry and os.path.isfile(python_exe) and \
                os.path.isfile(entry):
            return f'"{python_exe}" "{entry}" {tail}'
        return None

    def _agent_command(self, cfg):
        port = int(cfg.get("ipc_port", 47615))
        token = cfg.get("ipc_token", "")
        return self._app_command(cfg, f'agent --port {port} --token {token}')

    def _lock_command(self, cfg):
        return self._app_command(cfg, "lock")

    def _run_in_session(self, sid, cmd):
        """Start `cmd` as the user logged into console session `sid`, on their
        interactive desktop. Returns (process_handle, pid); the caller owns the
        handle. Raises on failure."""
        user_token = win32ts.WTSQueryUserToken(sid)
        dup = win32security.DuplicateTokenEx(
            user_token, win32security.SecurityImpersonation,
            win32con.MAXIMUM_ALLOWED, win32security.TokenPrimary)
        win32api.CloseHandle(user_token)
        try:
            env = win32profile.CreateEnvironmentBlock(dup, False)

            startup = win32process.STARTUPINFO()
            startup.dwFlags = win32con.STARTF_USESHOWWINDOW
            startup.wShowWindow = win32con.SW_HIDE
            startup.lpDesktop = "winsta0\\default"

            flags = (win32con.CREATE_UNICODE_ENVIRONMENT |
                     win32con.CREATE_NO_WINDOW)

            hProcess, hThread, pid, tid = win32process.CreateProcessAsUser(
                dup, None, cmd, None, None, False, flags, env, None, startup)
            win32api.CloseHandle(hThread)
            return hProcess, pid
        finally:
            win32api.CloseHandle(dup)

    def _launch_agent(self, sid):
        with self.lock:
            cfg = dict(self.cfg)
        cmd = self._agent_command(cfg)
        if not cmd:
            log.error("Cannot launch agent; no valid app_exe/python_exe in config")
            return
        try:
            hProcess, pid = self._run_in_session(sid, cmd)
        except Exception:
            log.exception("Failed to launch agent in session %s", sid)
            return
        self.agent_handle = hProcess
        self.agent_session = sid
        log.info("Launched agent pid=%s in session %s", pid, sid)

    def _lock_session(self, sid):
        """Lock the interactive session (secure Windows lock screen) by running
        a one-shot 'lock' helper as the logged-on user."""
        with self.lock:
            cfg = dict(self.cfg)
        cmd = self._lock_command(cfg)
        if not cmd:
            log.error("Cannot lock session; no valid app_exe/python_exe in config")
            return
        try:
            hProcess, pid = self._run_in_session(sid, cmd)
            win32api.CloseHandle(hProcess)
            log.info("Locked session %s (agent went down while blocked)", sid)
        except Exception:
            log.exception("Failed to lock session %s", sid)


# --------------------------------------------------------------------------- #
# Service lifecycle helpers (used by the installer)
# --------------------------------------------------------------------------- #
def _service_binary():
    """Command the SCM should run to host the service.

    Packaged: the frozen exe with the --service-run marker.
    From source: pythonw.exe running datycho.py with the marker.
    """
    if getattr(sys, "frozen", False):
        return sys.executable, SERVICE_RUN_ARG
    entry = os.path.join(os.path.dirname(os.path.abspath(__file__)), "datycho.py")
    return sys.executable, f'"{entry}" {SERVICE_RUN_ARG}'


def install_service(exe=None, args=None):
    """Register the service. `exe`/`args` let the installer point the SCM at the
    *installed* exe (in Program Files) rather than wherever install is running
    from (e.g. a flash drive). Defaults suit running from source."""
    if exe is None:
        exe, args = _service_binary()
    if args is None:
        args = SERVICE_RUN_ARG
    win32serviceutil.InstallService(
        pythonClassString=f"{__name__}.DatychoService",
        serviceName=branding.SERVICE_NAME,
        displayName=branding.SERVICE_DISPLAY,
        description=branding.SERVICE_DESCRIPTION,
        startType=win32service.SERVICE_AUTO_START,
        exeName=exe,
        exeArgs=args,
    )


def remove_service():
    try:
        win32serviceutil.StopService(branding.SERVICE_NAME)
    except Exception:
        pass
    win32serviceutil.RemoveService(branding.SERVICE_NAME)


def start_service():
    win32serviceutil.StartService(branding.SERVICE_NAME)


def run_service_dispatch():
    """Entry point when the SCM launches us with the --service-run marker."""
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(DatychoService)
    servicemanager.StartServiceCtrlDispatcher()


if __name__ == "__main__":
    # Dev convenience: `python service.py install|start|stop|remove`.
    win32serviceutil.HandleCommandLine(DatychoService)
