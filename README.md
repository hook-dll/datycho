# datychö

Screen-time control for a Windows 11 PC. Intended use: restrict your kid from using PC too much. 

Enforces a daily time window and a daily usage limit for chosen Windows accounts, blocks the screen when time is up, and
requires a rotating authenticator code to grant extra time. Ships as a single
`.exe` — no software needed on the target PC.

- **Time window** (e.g. 10:00–21:00) and **daily limit** (e.g. 120 min)
- **Applies only to the accounts you choose** — a parent's account is untouched.
- **Locked time is free** — pressing **Win + L** shows the normal Windows lock
  screen and that time is not counted. Teach your kid to lock PC with Win + L when he's afk so his allowed time won't drain while he went for snacks.
- **Small always-on-top timer** showing time left.
- **Block screen** when out of time; entering the current 6-digit code from your Google
  authenticator app grants a temporary override. The code rotates every 30s, so
  there's no static password for a child to learn.
- Runs as a **LocalSystem Windows service** a non-admin child can't kill, and
  **relaunches the timer/overlay within ~1s** if it's closed.
- **Cyrillic account names** are fully supported (read, matched, displayed).



---

## For parents: install on the kid's PC (or your PC if your kid uses it)

### Requirements:

- A kid **must** use his own **non-admin** account
- A parent **must** have Google/Microsoft Authenticator or Authy on the phone.

### Install

1. Download and open **`datychö-Setup`** folder.
2. Run **`datycho.exe`**. Approve the
   **UAC / administrator** prompt. (This is an unsigned app: so if SmartScreen warns, choose
   *More info → Run anyway*.)
3. In the wizard:
   - **tick the kid's Windows account(s)**
   - set the window, daily limit, override length and timer position,
   - **scan the QR** with Google/Microsoft Authenticator or Authy (or type the
     key), and click **Check** to confirm a code works,
   - click **Install**.

The program installs to `C:\Program Files\datycho\

### Re-configure after install

Not available. Remove program from PC (with admin rights/password), reinstall.


### Uninstall
- **Settings → Apps → datychö → Uninstall**
  (Add or remove programs). Approve the UAC prompt.

---

## For developers

### Layout
| File | Role |
|------|------|
| `datycho.py` | Entry point; dispatches modes (`install` default, `agent`, `uninstall`, `--service-run`) |
| `branding.py` | All names and install paths (ASCII internals, `datychö` display) |
| `service.py` | LocalSystem service: tracking, enforcement, IPC, agent supervision, install helpers |
| `agent.py` | User-session GUI: timer + block overlay + lock detection |
| `installer_gui.py` | Tkinter setup wizard and uninstaller |
| `common.py` | Config, state, TOTP, account enumeration, lock/session detection |
| `build.py` | PyInstaller build → `dist/datychö-Setup/` |

### Run from source
```powershell
pip install -r requirements.txt
python datycho.py            # opens the wizard (self-elevates via UAC)
```

### Build the exe
```powershell
pip install -r requirements.txt pyinstaller
python build.py
# -> dist/datychö-Setup/datycho.exe
```

### How the parts talk
The service is authoritative; the agent polls it over `127.0.0.1` (default port
47615) with a random per-install token, reporting lock state and receiving the
block/allow status. Overrides are authorized by a TOTP code (RFC 6238); only the
shared secret is stored, in `C:\ProgramData\datycho\config.json`.

---

## Notes & limits (honest)
- **Unsigned exe** → SmartScreen/antivirus may warn; code signing needs a paid
  certificate (not included).
- The "can't be killed" guarantee is about the **service** (needs admin to stop).
  The overlay is a normal top-most window the service respawns quickly; there's a
  ~1s gap on each kill, and it doesn't hard-block all keyboard input. Sufficient
  for a young, non-technical child.
- An **administrator** account can always stop the service — keep the child on a
  standard account.
- Override friction is intentional: each extension needs a fresh code from your
  phone, so a learned secret is worthless.

Logs: `C:\ProgramData\datycho\logs\`.
