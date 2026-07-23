"""
datychö — GUI setup wizard and uninstaller (Tkinter).

Both run elevated (the packaged exe carries an admin manifest). The wizard lets a
parent pick which Windows accounts to restrict (accounts with Cyrillic-only
names are pre-ticked), set the window/limit, enroll an authenticator app via a
scannable QR, then copies the program to Program Files and installs the service.
"""

import os
import sys
import shutil
import secrets
import winreg
import ctypes
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox

import common
import branding
import service


# --------------------------------------------------------------------------- #
# Elevation & environment
# --------------------------------------------------------------------------- #
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _relaunch_elevated(mode):
    """Relaunch this program elevated (UAC prompt) in the given mode. Returns
    True if a relaunch was triggered (caller should exit)."""
    exe = sys.executable
    if getattr(sys, "frozen", False):
        params = mode
    else:
        entry = os.path.join(_source_dir(), "datycho.py")
        params = f'"{entry}" {mode}'
    # SW_SHOWNORMAL = 1
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    return int(rc) > 32


def _is_frozen():
    return getattr(sys, "frozen", False)


def _source_dir():
    """Folder to copy into Program Files (packaged build only)."""
    if _is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _installed_exe():
    return os.path.join(branding.INSTALL_DIR, "datycho.exe")


# --------------------------------------------------------------------------- #
# QR rendering (no image library — draw the matrix on a Canvas)
# --------------------------------------------------------------------------- #
def _draw_qr(canvas, uri, cell=5):
    import qrcode
    qr = qrcode.QRCode(border=2, box_size=1,
                       error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(uri)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    n = len(matrix)
    size = n * cell
    canvas.config(width=size, height=size)
    canvas.delete("all")
    canvas.create_rectangle(0, 0, size, size, fill="white", outline="white")
    for r, row in enumerate(matrix):
        for c, on in enumerate(row):
            if on:
                x, y = c * cell, r * cell
                canvas.create_rectangle(x, y, x + cell, y + cell,
                                        fill="black", outline="black")


# --------------------------------------------------------------------------- #
# Install steps
# --------------------------------------------------------------------------- #
def _copy_program_files():
    src = _source_dir()
    dst = branding.INSTALL_DIR
    if os.path.normcase(os.path.abspath(src)) == os.path.normcase(
            os.path.abspath(dst)):
        return  # running from the install location already (repair/re-run)
    os.makedirs(dst, exist_ok=True)
    shutil.copytree(src, dst, dirs_exist_ok=True)


def _register_uninstall():
    exe = _installed_exe()
    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, branding.UNINSTALL_KEY) as k:
        winreg.SetValueEx(k, "DisplayName", 0, winreg.REG_SZ, branding.APP_DISPLAY)
        winreg.SetValueEx(k, "DisplayVersion", 0, winreg.REG_SZ, branding.VERSION)
        winreg.SetValueEx(k, "Publisher", 0, winreg.REG_SZ, branding.PUBLISHER)
        winreg.SetValueEx(k, "InstallLocation", 0, winreg.REG_SZ,
                          branding.INSTALL_DIR)
        winreg.SetValueEx(k, "DisplayIcon", 0, winreg.REG_SZ, exe)
        winreg.SetValueEx(k, "UninstallString", 0, winreg.REG_SZ,
                          f'"{exe}" uninstall')
        winreg.SetValueEx(k, "NoModify", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(k, "NoRepair", 0, winreg.REG_DWORD, 1)


def _remove_uninstall_reg():
    try:
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, branding.UNINSTALL_KEY)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _configure_launch(cfg):
    """Record how the service should start the agent."""
    if _is_frozen():
        cfg["app_exe"] = _installed_exe()
        cfg["python_exe"] = ""
        cfg["entry_script"] = ""
    else:
        pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        cfg["python_exe"] = pyw if os.path.isfile(pyw) else sys.executable
        cfg["entry_script"] = os.path.join(_source_dir(), "datycho.py")
        cfg["app_exe"] = ""


def perform_install(cfg):
    """Do the actual install work. Raises if the essential steps (files, config,
    service) fail. Returns a warning string for any non-essential step."""
    common.ensure_dirs()
    if _is_frozen():
        _copy_program_files()
    _configure_launch(cfg)
    common.save_config(cfg)
    # Start every install from a clean slate: clear any leftover used-time or
    # active override from a previous install (state.json survives sc delete).
    common.save_state(common.default_state())

    # (Re)install the service, pointing the SCM at the installed exe so it
    # survives the flash drive being removed.
    try:
        service.remove_service()
    except Exception:
        pass
    if _is_frozen():
        service.install_service(exe=_installed_exe(),
                                args=service.SERVICE_RUN_ARG)
    else:
        service.install_service()
    service.start_service()

    # Registering in "Add or remove programs" is best-effort — the service is
    # already installed and running, so never fail the whole install over it.
    try:
        _register_uninstall()
        return ""
    except Exception as e:
        return f"Note: could not add an 'Add or remove programs' entry ({e}). " \
               "You can still uninstall by running datycho.exe uninstall."


# --------------------------------------------------------------------------- #
# Wizard UI
# --------------------------------------------------------------------------- #
class Wizard:
    CORNERS = ["top-right", "top-left", "top-center",
               "bottom-right", "bottom-left", "bottom-center"]

    def __init__(self):
        try:
            existing = common.load_config()
        except (OSError, ValueError):
            existing = common.default_config()
        self.cfg = existing
        # A secret is generated up front so the QR matches what gets saved.
        if not self.cfg.get("totp_secret"):
            self.cfg["totp_secret"] = common.generate_totp_secret()
        if not self.cfg.get("ipc_token"):
            self.cfg["ipc_token"] = secrets.token_hex(16)
        self.secret = self.cfg["totp_secret"]
        self.code_ok = False        # a code has been verified this session

        self.root = tk.Tk()
        self.root.title(f"{branding.APP_DISPLAY} — Setup")
        self.root.minsize(560, 420)
        self.user_vars = {}
        self._build()
        self._fit_window()

    def _fit_window(self):
        """Size the window to its content (so nothing is hidden on open),
        capped to the screen; center it. Scrolling covers the rare overflow."""
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        # Natural height of the scrollable content + fixed header/action bars.
        content = self.body.winfo_reqheight()
        chrome = self.header.winfo_reqheight() + self.act.winfo_reqheight() + 48
        h = min(content + chrome, int(sh * 0.92))
        w = min(760, int(sw * 0.9))
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 3)
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    # ----- layout ----- #
    def _make_scrollable(self):
        """A vertically scrollable content frame, so the window can be any size
        and all content stays reachable."""
        container = tk.Frame(self.root)
        container.pack(fill="both", expand=True)
        canvas = tk.Canvas(container, highlightthickness=0)
        vs = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(canvas)
        win = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfigure(win, width=e.width))
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(int(-e.delta / 120),
                                                      "units"))
        return inner

    def _build(self):
        pad = {"padx": 12, "pady": 6}

        # Header (fixed, top).
        self.header = tk.Label(self.root, text=f"{branding.APP_DISPLAY} setup",
                               font=("Segoe UI", 16, "bold"))
        self.header.pack(anchor="w", **pad)

        # Action bar (fixed, bottom) — packed before the scroll area so it is
        # always visible no matter how small the window is.
        act = self.act = tk.Frame(self.root)
        act.pack(fill="x", side="bottom", **pad)
        self.hint = tk.Label(
            act, text="Tick an account and verify a code to enable Install.",
            fg="#666", wraplength=660, justify="left")
        self.hint.pack(anchor="w")
        self.status = tk.Label(act, text="", fg="#036", wraplength=660,
                               justify="left")
        self.status.pack(anchor="w")
        self.install_btn = tk.Button(
            act, text="Install", font=("Segoe UI", 12, "bold"),
            bg="#2563eb", fg="white", activebackground="#1d4ed8",
            disabledforeground="#cbd5e1", relief="flat", padx=24, pady=8,
            cursor="hand2", state="disabled", command=self._install)
        self.install_btn.pack(anchor="e")

        # Scrollable content (fills the middle).
        body = self.body = self._make_scrollable()

        if not is_admin():
            tk.Label(body,
                     text="⚠ Not running as administrator — install will fail. "
                          "Right-click the exe and 'Run as administrator'.",
                     fg="#b00", wraplength=640, justify="left").pack(anchor="w",
                                                                     **pad)

        # Accounts
        box = ttk.LabelFrame(body, text="Accounts to restrict "
                             "(others stay unrestricted)")
        box.pack(fill="x", **pad)
        enforced_lower = {u.lower() for u in self.cfg.get("enforced_users", [])}
        try:
            users = common.list_local_users()
        except Exception as e:
            users = []
            tk.Label(box, text=f"Could not list accounts: {e}",
                     fg="#b00").pack(anchor="w", padx=8)
        if not users:
            tk.Label(box, text="(no local accounts found)").pack(anchor="w",
                                                                 padx=8)
        for name in users:
            # Nothing is pre-selected; the parent ticks the account(s) to
            # restrict. On a re-install we restore the previous selection.
            var = tk.BooleanVar(value=name.lower() in enforced_lower)
            var.trace_add("write", lambda *a: self._on_accounts_change())
            self.user_vars[name] = var
            tk.Checkbutton(box, text=name, variable=var,
                           font=("Segoe UI", 11)).pack(anchor="w", padx=8)

        # Rules
        rules = ttk.LabelFrame(body, text="Rules")
        rules.pack(fill="x", **pad)
        self.v_start = self._row(rules, "Allowed start (HH:MM)",
                                 self.cfg["window_start"], "time")
        self.v_end = self._row(rules, "Allowed end (HH:MM)",
                               self.cfg["window_end"], "time")
        self.v_limit = self._row(rules, "Daily limit (1–1440 min)",
                                 str(self.cfg["daily_limit_minutes"]), "int")
        self.v_override = self._row(rules, "Override per code (1–1440 min)",
                                    str(self.cfg["override_grant_minutes"]),
                                    "int")
        # Pin this PC's current UTC offset so a child changing the Windows time
        # zone (a non-admin action) can't shift the window or roll the day. The
        # value is captured at install in _collect; here we just show it.
        _off = common.current_utc_offset_minutes()
        tk.Label(rules,
                 text=(f"🕒 Time zone locked to {common.fmt_utc_offset(_off)} "
                       "(this PC). Changing the Windows time zone or clock no "
                       "longer adds time — a wrong clock blocks until a parent "
                       "enters a code."),
                 fg="#036", wraplength=520, justify="left").pack(
                     anchor="w", padx=8, pady=(2, 6))
        crow = tk.Frame(rules)
        crow.pack(fill="x", padx=8, pady=4)
        tk.Label(crow, text="Timer position", width=26, anchor="w").pack(
            side="left")
        self.v_corner = tk.StringVar(value=self.cfg.get("timer_corner",
                                                        "top-right"))
        corner_cb = ttk.Combobox(crow, textvariable=self.v_corner,
                                 values=self.CORNERS, state="readonly", width=18)
        corner_cb.pack(side="left")
        corner_cb.bind("<<ComboboxSelected>>",
                       lambda e: self._update_preview())

        # Timer font size (4–12) and opacity (0–100%), shown live in a floating
        # sample timer that matches the real one, so the parent can dial it in.
        frow = tk.Frame(rules)
        frow.pack(fill="x", padx=8, pady=4)
        tk.Label(frow, text="Timer font size", width=26, anchor="w").pack(
            side="left")
        self.v_font = tk.IntVar(value=int(self.cfg.get("timer_font_size", 9)))
        tk.Scale(frow, from_=4, to=12, orient="horizontal", length=220,
                 variable=self.v_font,
                 command=lambda *a: self._update_preview()).pack(side="left")

        orow = tk.Frame(rules)
        orow.pack(fill="x", padx=8, pady=4)
        tk.Label(orow, text="Timer opacity (%)", width=26, anchor="w").pack(
            side="left")
        self.v_opacity = tk.IntVar(
            value=int(round(float(self.cfg.get("timer_opacity", 0.65)) * 100)))
        tk.Scale(orow, from_=0, to=100, orient="horizontal", length=220,
                 variable=self.v_opacity,
                 command=lambda *a: self._update_preview()).pack(side="left")

        # Authenticator
        auth = ttk.LabelFrame(body, text="Authenticator app (required for overrides)")
        auth.pack(fill="x", **pad)
        tk.Label(auth, text="Scan this in Google/Microsoft Authenticator or "
                 "Authy, or type the key manually, then verify a code below:",
                 wraplength=640, justify="left").pack(anchor="w", padx=8,
                                                      pady=(4, 2))
        qr_wrap = tk.Frame(auth)
        qr_wrap.pack(anchor="w", padx=8)
        canvas = tk.Canvas(qr_wrap, highlightthickness=0)
        canvas.pack(side="left")
        self.qr_canvas = canvas
        try:
            _draw_qr(canvas, common.totp_uri(self.secret,
                                             account=self._account_label()))
        except Exception as e:
            tk.Label(qr_wrap, text=f"(QR unavailable: {e})", fg="#b00").pack()
        # Names the entry in the authenticator app, so multiple installs stay
        # distinguishable instead of all reading "datychö: parent".
        self.qr_caption = tk.Label(
            auth, text="", fg="#036", font=("Segoe UI", 9),
            wraplength=640, justify="left")
        self.qr_caption.pack(anchor="w", padx=8)
        self._update_qr_caption()
        side = tk.Frame(auth)
        side.pack(anchor="w", padx=8, pady=4, fill="x")
        tk.Label(side, text="Key:", font=("Segoe UI", 9)).pack(anchor="w")
        keyent = tk.Entry(side, font=("Consolas", 10), width=40)
        keyent.insert(0, self.secret)
        keyent.config(state="readonly")
        keyent.pack(anchor="w")
        vrow = tk.Frame(auth)
        vrow.pack(anchor="w", padx=8, pady=4)
        tk.Label(vrow, text="Verify a code:").pack(side="left")
        self.v_code = tk.StringVar()
        self.v_code.trace_add("write", lambda *a: self._on_code_change())
        code_entry = tk.Entry(vrow, textvariable=self.v_code,
                              font=("Consolas", 12), width=8, justify="center")
        code_entry.pack(side="left", padx=6)
        code_entry.bind("<Return>", lambda e: self._check_code())
        tk.Button(vrow, text="Check", command=self._check_code).pack(side="left")
        self.code_msg = tk.Label(vrow, text="")
        self.code_msg.pack(side="left", padx=6)

        # Floating live sample of the always-on-top timer.
        self._make_preview()
        self._update_preview()

    MAX_MINUTES = 1440  # minutes in a day

    # ----- authenticator entry naming ----- #
    def _account_label(self):
        """The account name shown for this install in the authenticator app.

        Combines the PC name with the restricted account(s) so a parent running
        datychö on more than one PC (or child) can tell the entries apart,
        instead of every install reading "datychö: parent"."""
        host = os.environ.get("COMPUTERNAME") or "PC"
        users = [n for n, v in self.user_vars.items() if v.get()]
        if users:
            return f"{host}: {', '.join(users)}"
        return host

    def _refresh_qr(self):
        if not hasattr(self, "qr_canvas"):
            return
        try:
            _draw_qr(self.qr_canvas,
                     common.totp_uri(self.secret, account=self._account_label()))
        except Exception:
            pass
        self._update_qr_caption()

    def _update_qr_caption(self):
        if hasattr(self, "qr_caption"):
            self.qr_caption.config(
                text=f"In your authenticator app this shows as:  "
                     f"{branding.APP_DISPLAY}: {self._account_label()}")

    # ----- live timer preview ----- #
    def _make_preview(self):
        self.preview = tk.Toplevel(self.root)
        self.preview.overrideredirect(True)
        self.preview.attributes("-topmost", True)
        self.preview.configure(bg="#1c2430")
        self.preview_label = tk.Label(
            self.preview, text="⏳ 1:23 left", fg="#e8edf2", bg="#1c2430",
            padx=8, pady=3)
        self.preview_label.pack()

    def _update_preview(self):
        if not hasattr(self, "preview") or not self.preview.winfo_exists():
            return
        self.preview_label.config(
            font=("Segoe UI", int(self.v_font.get()), "bold"))
        alpha = max(0.0, min(1.0, self.v_opacity.get() / 100.0))
        try:
            self.preview.attributes("-alpha", alpha)
        except tk.TclError:
            pass
        self.preview.deiconify()
        self.preview.update_idletasks()
        sw = self.preview.winfo_screenwidth()
        sh = self.preview.winfo_screenheight()
        w = self.preview.winfo_width()
        margin = 12
        positions = {
            "top-right": (sw - w - margin, margin),
            "top-left": (margin, margin),
            "top-center": ((sw - w) // 2, margin),
            "bottom-right": (sw - w - margin, sh - 60),
            "bottom-left": (margin, sh - 60),
            "bottom-center": ((sw - w) // 2, sh - 60),
        }
        x, y = positions.get(self.v_corner.get(), positions["top-right"])
        self.preview.geometry(f"+{int(x)}+{int(y)}")

    def _row(self, parent, label, value, kind="text"):
        row = tk.Frame(parent)
        row.pack(fill="x", padx=8, pady=4)
        tk.Label(row, text=label, width=26, anchor="w").pack(side="left")
        var = tk.StringVar(value=value)
        ent = tk.Entry(row, textvariable=var, width=20)
        if kind == "time":
            vcmd = (self.root.register(self._vld_time), "%P")
            ent.config(validate="key", validatecommand=vcmd)
        elif kind == "int":
            vcmd = (self.root.register(self._vld_int), "%P")
            ent.config(validate="key", validatecommand=vcmd)
        ent.pack(side="left")
        return var

    # ----- live keystroke filters (block obviously-wrong characters) ----- #
    @staticmethod
    def _vld_time(proposed):
        # Allow only digits and a single colon, max "HH:MM".
        if len(proposed) > 5:
            return False
        return all(c.isdigit() or c == ":" for c in proposed) \
            and proposed.count(":") <= 1

    @staticmethod
    def _vld_int(proposed):
        # Allow only up to 4 digits (range is enforced on Install).
        return proposed == "" or (proposed.isdigit() and len(proposed) <= 4)

    # ----- strict parsing with clear messages ----- #
    def _parse_time(self, text, name):
        parts = text.strip().split(":")
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            h, m = int(parts[0]), int(parts[1])
            if 0 <= h <= 23 and 0 <= m <= 59:
                return f"{h:02d}:{m:02d}"
        raise ValueError(
            f"Enter the {name} time as HH:MM between 00:00 and 23:59 "
            f"(e.g. 10:00) — got \"{text.strip()}\".")

    def _parse_minutes(self, text, name):
        t = text.strip()
        if not t.isdigit() or not (1 <= int(t) <= self.MAX_MINUTES):
            raise ValueError(
                f"{name} must be a whole number of minutes from 1 to "
                f"{self.MAX_MINUTES} (24 hours) — got \"{t}\".")
        return int(t)

    # ----- actions ----- #
    def _on_accounts_change(self):
        # A changed account selection updates both the Install gate and the
        # authenticator entry name (which folds in the ticked account(s)).
        self._update_install_state()
        self._refresh_qr()

    def _update_install_state(self):
        any_acc = any(v.get() for v in self.user_vars.values())
        ready = any_acc and self.code_ok
        self.install_btn.config(state="normal" if ready else "disabled")
        if ready:
            self.hint.config(text="Ready to install.", fg="#070")
        elif not any_acc:
            self.hint.config(text="Tick at least one account to restrict.",
                             fg="#666")
        else:
            self.hint.config(text="Verify a code from your authenticator app.",
                             fg="#666")

    def _on_code_change(self):
        # Any edit invalidates a previous verification.
        self.code_ok = False
        self.code_msg.config(text="")
        self._update_install_state()

    def _check_code(self):
        if common.verify_totp(self.secret, self.v_code.get()):
            self.code_ok = True
            self.code_msg.config(text="✓ works", fg="#070")
        else:
            self.code_ok = False
            self.code_msg.config(text="✗ no match", fg="#b00")
        self._update_install_state()

    def _collect(self):
        cfg = dict(self.cfg)
        cfg["enforced_users"] = [n for n, v in self.user_vars.items()
                                 if v.get()]
        cfg["window_start"] = self._parse_time(self.v_start.get(), "start")
        cfg["window_end"] = self._parse_time(self.v_end.get(), "end")
        cfg["daily_limit_minutes"] = self._parse_minutes(
            self.v_limit.get(), "Daily limit")
        cfg["override_grant_minutes"] = self._parse_minutes(
            self.v_override.get(), "Override length")
        cfg["timer_corner"] = self.v_corner.get()
        cfg["timer_font_size"] = int(self.v_font.get())
        cfg["timer_opacity"] = round(self.v_opacity.get() / 100.0, 3)
        # Pin the offset as of install; enforcement uses it instead of the live
        # (child-changeable) OS time zone.
        cfg["utc_offset_minutes"] = common.current_utc_offset_minutes()
        return cfg

    def _install(self):
        if not is_admin():
            messagebox.showerror(branding.APP_DISPLAY,
                                 "Please run as administrator.")
            return
        try:
            cfg = self._collect()
        except ValueError as e:
            messagebox.showerror(branding.APP_DISPLAY, str(e))
            return
        # The Install button is only enabled with ≥1 account and a verified
        # code, but guard anyway.
        if not cfg["enforced_users"] or not self.code_ok:
            return
        if hasattr(self, "preview") and self.preview.winfo_exists():
            self.preview.withdraw()
        self.status.config(text="Installing…")
        self.root.update_idletasks()
        try:
            warn = perform_install(cfg)
        except Exception as e:
            messagebox.showerror(branding.APP_DISPLAY, f"Install failed:\n{e}")
            self.status.config(text="Install failed.")
            return
        who = ", ".join(cfg["enforced_users"])
        msg = (f"{branding.APP_DISPLAY} is installed and running.\n\n"
               f"Applies to: {who}\n"
               f"Window: {cfg['window_start']}–{cfg['window_end']}\n"
               f"Limit: {cfg['daily_limit_minutes']} min/day\n\n"
               "Keep your authenticator app — you'll need a code to grant extra "
               "time. Remove via 'Add or remove programs'.")
        if warn:
            msg += f"\n\n{warn}"
        messagebox.showinfo(branding.APP_DISPLAY, msg)
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #
def run_install():
    if not is_admin():
        _relaunch_elevated("install")
        return
    Wizard().run()


def run_uninstall():
    if not is_admin():
        _relaunch_elevated("uninstall")
        return
    root = tk.Tk()
    root.withdraw()
    if not messagebox.askyesno(
            branding.APP_DISPLAY,
            f"Remove {branding.APP_DISPLAY} and its settings from this PC?"):
        return
    try:
        service.remove_service()
    except Exception:
        pass
    _remove_uninstall_reg()

    # Kill any running agent and delete the folders after we exit (we may be
    # running from inside the install folder).
    targets = f'rmdir /s /q "{branding.INSTALL_DIR}" & rmdir /s /q "{branding.DATA_DIR}"'
    subprocess.Popen(
        f'cmd /c ping 127.0.0.1 -n 3 >nul & taskkill /f /im datycho.exe >nul 2>&1 & {targets}',
        shell=True,
        creationflags=0x00000008 | 0x00000200,  # DETACHED_PROCESS | NEW_GROUP
    )
    messagebox.showinfo(branding.APP_DISPLAY,
                        f"{branding.APP_DISPLAY} has been removed.")
    root.destroy()
