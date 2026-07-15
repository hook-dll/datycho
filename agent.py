"""
KidControlPc GUI agent (runs in the child's interactive session).

It is launched and supervised by the service. If the child ends it in Task
Manager, the service relaunches it within ~1 second.

Two windows:
  * A small always-on-top timer showing time left / status.
  * A fullscreen top-most block overlay (shown only while blocked) with a
    parent-password box that requests a temporary override.

All policy decisions live in the service; the agent only displays state and
relays the password.
"""

import json
import socket
import argparse
import tkinter as tk

import common
import branding

POLL_MS = 1000
CONNECT_TIMEOUT = 3.0


def fmt_hms(seconds):
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m}:{s:02d}"


class ServiceClient:
    def __init__(self, port, token):
        self.port = port
        self.token = token

    def request(self, payload):
        payload = {**payload, "token": self.token}
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        try:
            s.connect(("127.0.0.1", self.port))
            s.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            data = b""
            while b"\n" not in data and len(data) < 8192:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
            line = data.split(b"\n", 1)[0].decode("utf-8", "replace")
            return json.loads(line) if line.strip() else {}
        finally:
            try:
                s.close()
            except OSError:
                pass

    def status(self):
        return self.request({"cmd": "status"})

    def override(self, code):
        return self.request({"cmd": "override", "code": code})

    def relock(self):
        return self.request({"cmd": "relock"})


class TimerWindow:
    """Small, borderless, always-on-top time indicator."""

    def __init__(self, root):
        self.root = root
        self.win = tk.Toplevel(root)
        self.win.overrideredirect(True)
        self.win.attributes("-topmost", True)
        self.win.configure(bg="#1c2430")
        self.opacity = 0.65

        self.label = tk.Label(
            self.win, text="…", font=("Segoe UI", 9, "bold"),
            fg="#e8edf2", bg="#1c2430", padx=8, pady=3,
        )
        self.label.pack()
        # A right-click on the timer lets a parent end an active override.
        self.label.bind("<Button-3>", self._parent_menu)
        self.corner = "top-right"
        self.on_relock = None
        self.shown = True
        self._apply_opacity(self.opacity)
        self._place()

    def _apply_opacity(self, value):
        try:
            self.win.attributes("-alpha", max(0.3, min(1.0, float(value))))
        except (tk.TclError, ValueError):
            pass

    def hide(self):
        if self.shown:
            self.win.withdraw()
            self.shown = False

    def _ensure_shown(self):
        if not self.shown:
            self.win.deiconify()
            self.shown = True

    def _place(self):
        self.win.update_idletasks()
        sw = self.win.winfo_screenwidth()
        w = self.win.winfo_width()
        margin = 12
        positions = {
            "top-right": (sw - w - margin, margin),
            "top-left": (margin, margin),
            "top-center": ((sw - w) // 2, margin),
            "bottom-right": (sw - w - margin,
                             self.win.winfo_screenheight() - 60),
            "bottom-left": (margin, self.win.winfo_screenheight() - 60),
            "bottom-center": ((sw - w) // 2,
                              self.win.winfo_screenheight() - 60),
        }
        x, y = positions.get(self.corner, positions["top-right"])
        self.win.geometry(f"+{int(x)}+{int(y)}")

    def update(self, status):
        self._ensure_shown()
        self.corner = status.get("timer_corner", self.corner)
        opacity = status.get("timer_opacity", self.opacity)
        if opacity != self.opacity:
            self.opacity = opacity
            self._apply_opacity(opacity)
        warn = status.get("warn_minutes", 10) * 60
        if status.get("override"):
            rem = status.get("override_remaining", 0)
            text = f"🔓 Override {fmt_hms(rem)}"
            fg = "#f87171" if rem <= warn else "#6ee7b7"
        else:
            remaining = status.get("remaining", 0)
            text = f"⏳ {fmt_hms(remaining)} left"
            fg = "#f87171" if remaining <= warn else "#e8edf2"
        self.label.config(text=text, fg=fg)
        self.win.attributes("-topmost", True)
        self._place()

    def _parent_menu(self, event):
        if self.on_relock:
            self.on_relock()


class BlockOverlay:
    """Fullscreen top-most blocker with a parent-password box."""

    def __init__(self, root, client):
        self.root = root
        self.client = client
        self.visible = False
        self.win = tk.Toplevel(root)
        self.win.withdraw()
        self.win.configure(bg="#0f1720")
        self.win.protocol("WM_DELETE_WINDOW", lambda: None)  # ignore Alt-F4

        wrap = tk.Frame(self.win, bg="#0f1720")
        wrap.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(wrap, text="🔒", font=("Segoe UI Emoji", 64),
                 fg="#e8edf2", bg="#0f1720").pack(pady=(0, 10))
        self.headline = tk.Label(
            wrap, text="Time's up", font=("Segoe UI", 30, "bold"),
            fg="#e8edf2", bg="#0f1720")
        self.headline.pack()
        self.detail = tk.Label(
            wrap, text="", font=("Segoe UI", 15),
            fg="#9aa7b4", bg="#0f1720", wraplength=560, justify="center")
        self.detail.pack(pady=(8, 24))

        tk.Label(wrap, text="Parent: enter the 6-digit code from your "
                 "authenticator app", font=("Segoe UI", 12), fg="#9aa7b4",
                 bg="#0f1720").pack()
        self.entry = tk.Entry(wrap, font=("Consolas", 22), width=8,
                              justify="center")
        self.entry.pack(pady=8)
        self.entry.bind("<Return>", lambda e: self._submit())

        self.btn = tk.Button(wrap, text="Unlock", font=("Segoe UI", 12, "bold"),
                             command=self._submit, bg="#2563eb", fg="white",
                             activebackground="#1d4ed8", relief="flat",
                             padx=20, pady=6, cursor="hand2")
        self.btn.pack(pady=(4, 0))
        self.msg = tk.Label(wrap, text="", font=("Segoe UI", 11),
                            fg="#f87171", bg="#0f1720")
        self.msg.pack(pady=(12, 0))

    def show(self, status):
        headline = {
            "outside_window": "Not computer time",
            "limit_reached": "Time's up for today",
        }.get(status.get("reason"), "Locked")
        self.headline.config(text=headline)
        self.detail.config(text=status.get("message", ""))
        if not self.visible:
            self.win.deiconify()
            self.win.attributes("-fullscreen", True)
            self.win.attributes("-topmost", True)
            self.visible = True
        # Keep it on top and focused even if something tries to surface.
        self.win.attributes("-topmost", True)
        self.win.lift()
        self.entry.focus_force()

    def hide(self):
        if self.visible:
            self.win.attributes("-fullscreen", False)
            self.win.withdraw()
            self.visible = False
            self.entry.delete(0, tk.END)
            self.msg.config(text="")

    def _submit(self):
        code = self.entry.get()
        self.entry.delete(0, tk.END)
        try:
            resp = self.client.override(code)
        except OSError:
            self.msg.config(text="Cannot reach the control service.")
            return
        if resp.get("ok"):
            self.msg.config(text="")
            self.hide()  # service will report allowed on next poll
        else:
            self.msg.config(text="Incorrect or expired code. Try the newest one.")


class App:
    def __init__(self, port, token):
        self.client = ServiceClient(port, token)
        self.root = tk.Tk()
        self.root.withdraw()  # hidden controller window
        self.timer = TimerWindow(self.root)
        self.overlay = BlockOverlay(self.root, self.client)
        self.timer.on_relock = self._parent_relock
        self.root.after(200, self._poll)

    def _parent_relock(self):
        """Parent right-clicked the timer to end an active override early."""
        # Only meaningful during an override; a password isn't required to make
        # the rules stricter again.
        try:
            self.client.relock()
        except OSError:
            pass

    def _poll(self):
        # Lock detection lives in the service (via OS session-change events).
        try:
            status = self.client.status()
        except OSError:
            status = None

        if status and status.get("ok", True) and "blocked" in status:
            if status.get("monitored", True):
                self.timer.update(status)
            else:
                # Unmonitored account (e.g. a parent's): no timer, no overlay.
                self.timer.hide()
            if status.get("blocked"):
                self.overlay.show(status)
            else:
                self.overlay.hide()
        # If the service is briefly unreachable, keep the last view and retry.
        self.root.after(POLL_MS, self._poll)

    def run(self):
        self.root.mainloop()


def main(argv=None):
    ap = argparse.ArgumentParser(prog=f"{branding.APP_ID} agent")
    ap.add_argument("--port", type=int, default=47615)
    ap.add_argument("--token", default="")
    args = ap.parse_args(argv)
    App(args.port, args.token).run()


if __name__ == "__main__":
    main()
