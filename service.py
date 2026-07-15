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
        self._roll_day_if_needed()

        ipc_thread = threading.Thread(target=self._ipc_server, daemon=True)
        ipc_thread.start()

        log.info("Service started; window=%s limit=%smin",
                 self.status.get("window"), self.cfg.get("daily_limit_minutes"))

        self.running = True
        last_persist = time.monotonic()
        last_blocked = None
        tick = 0

        while self.running:
            if tick % CONFIG_RELOAD_EVERY == 0:
                self._reload_config()
            tick += 1

            self._compute_tick()
            self._supervise_agent()

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

    def _roll_day_if_needed(self):
        today = common.today_str()
        if self.state.get("date") != today:
            self.state["date"] = today
            self.state["used_seconds"] = 0
            self.state["override_until"] = 0.0

    def _compute_tick(self):
        with self.lock:
            cfg = dict(self.cfg)
            state = self.state

        self._roll_day_if_needed()

        from datetime import datetime
        now = datetime.now()
        now_epoch = time.time()

        try:
            start = common.parse_hhmm(cfg["window_start"])
            end = common.parse_hhmm(cfg["window_end"])
        except Exception:
            start = common.parse_hhmm("00:00")
            end = common.parse_hhmm("23:59")

        limit = int(cfg["daily_limit_minutes"]) * 60
        used = int(state["used_seconds"])
        override_until = float(state.get("override_until", 0))
        override_active = now_epoch < override_until
        override_remaining = int(max(0, override_until - now_epoch)) \
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

        within = common.in_window(now.time(), start, end)
        remaining = max(0, limit - used)

        if not monitored:
            # This account isn't subject to the rules (e.g. a parent's login).
            allowed, reason = True, "unmonitored"
            message = ""
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

        # Show the block overlay only when the screen is actively in use
        # (session present and unlocked) but not allowed. A voluntarily locked
        # PC shows the normal Windows lock screen — nothing to overlay.
        blocked = session_active and not is_locked and not allowed

        with self.lock:
            self.status = {
                "blocked": blocked,
                "reason": reason,
                "monitored": monitored,
                "remaining": int(remaining),
                "used": int(used),
                "limit": int(limit),
                "override": override_active and monitored,
                "override_remaining": override_remaining,
                "window": f"{cfg['window_start']}–{cfg['window_end']}",
                "warn_minutes": int(cfg.get("warn_minutes", 10)),
                "timer_corner": cfg.get("timer_corner", "top-right"),
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
        if not common.verify_totp(cfg.get("totp_secret"), code):
            log.info("Override attempt with incorrect/expired code")
            return False
        grant = int(cfg.get("override_grant_minutes", 60)) * 60
        self.state["override_until"] = time.time() + grant
        self._persist()
        log.info("Parent override granted for %s minutes",
                 cfg.get("override_grant_minutes"))
        return True

    def _relock(self):
        """End any active override immediately (parent 'lock now')."""
        self.state["override_until"] = 0.0
        self._persist()
        log.info("Override ended by parent (re-lock)")

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

    def _supervise_agent(self):
        sid = common.get_active_console_session()
        if sid is None:
            # No interactive user; nothing to supervise.
            self._close_agent_handle()
            return
        if self._agent_alive() and self.agent_session == sid:
            return
        # Either the agent is dead, never started, or the console session
        # changed (fast user switch / re-logon) -> (re)launch it.
        self._close_agent_handle()
        self._launch_agent(sid)

    def _close_agent_handle(self):
        if self.agent_handle is not None:
            try:
                win32api.CloseHandle(self.agent_handle)
            except Exception:
                pass
            self.agent_handle = None
            self.agent_session = None

    def _agent_command(self, cfg):
        """Build the command line that launches the GUI agent, for either the
        packaged (frozen exe) or the from-source layout."""
        port = int(cfg.get("ipc_port", 47615))
        token = cfg.get("ipc_token", "")
        tail = f'agent --port {port} --token {token}'
        app_exe = cfg.get("app_exe") or ""
        if app_exe and os.path.isfile(app_exe):
            return f'"{app_exe}" {tail}'
        python_exe = cfg.get("python_exe") or ""
        entry = cfg.get("entry_script") or ""
        if python_exe and entry and os.path.isfile(python_exe) and \
                os.path.isfile(entry):
            return f'"{python_exe}" "{entry}" {tail}'
        return None

    def _launch_agent(self, sid):
        with self.lock:
            cfg = dict(self.cfg)
        cmd = self._agent_command(cfg)
        if not cmd:
            log.error("Cannot launch agent; no valid app_exe/python_exe in config")
            return
        try:
            # Get the token of the logged-on user in that session and start the
            # agent as that user, on their interactive desktop.
            user_token = win32ts.WTSQueryUserToken(sid)
            dup = win32security.DuplicateTokenEx(
                user_token, win32security.SecurityImpersonation,
                win32con.MAXIMUM_ALLOWED, win32security.TokenPrimary)
            win32api.CloseHandle(user_token)

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
            win32api.CloseHandle(dup)

            self.agent_handle = hProcess
            self.agent_session = sid
            log.info("Launched agent pid=%s in session %s", pid, sid)
        except Exception:
            log.exception("Failed to launch agent in session %s", sid)


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
