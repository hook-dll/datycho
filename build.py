"""
Build datycho.exe with PyInstaller (onedir) and lay it out as a flash-drive
folder named "datychö-Setup".

Run on a machine with Python + the requirements installed:

    pip install -r requirements.txt pyinstaller
    python build.py

Output: dist/datychö-Setup/  (contains datycho.exe + _internal). Copy that whole
folder to a flash drive; on the target PC run datycho.exe.
"""

import os
import sys
import time
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
SETUP_DIR_NAME = "datychö-Setup"


def _force_rmtree(path, tries=6):
    """Remove a tree, retrying past transient locks (e.g. antivirus scanning
    freshly written files)."""
    for i in range(tries):
        if not os.path.exists(path):
            return
        try:
            shutil.rmtree(path)
            return
        except Exception:
            time.sleep(1)
    if os.path.exists(path):
        shutil.rmtree(path)  # final try; let it raise with a real error


def main():
    # The console may be a legacy code page (e.g. cp1251) that can't encode the
    # "ö" in our paths; force UTF-8 so status output never crashes the build.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    for d in ("build", "dist"):
        _force_rmtree(os.path.join(HERE, d))

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--name", "datycho",
        "--onedir",
        "--windowed",                       # no console window (GUI app)
        # Normal (asInvoker) manifest — the installer self-elevates via UAC, so
        # the agent can still run as the standard-user child without a prompt.
        "--hidden-import", "win32timezone",
        "--collect-submodules", "qrcode",
        "datycho.py",
    ]
    print("Running:", " ".join(cmd))
    subprocess.check_call(cmd, cwd=HERE)

    built = os.path.join(DIST, "datycho")
    if not os.path.isdir(built):
        print("ERROR: expected build output not found:", built)
        sys.exit(1)

    setup_dir = os.path.join(DIST, SETUP_DIR_NAME)
    _force_rmtree(setup_dir)
    os.rename(built, setup_dir)

    exe = os.path.join(setup_dir, "datycho.exe")
    print("\n[OK] Built:", exe)
    print("   Flash-drive folder:", setup_dir)
    print("   Copy that whole folder to the USB stick; run datycho.exe on the "
          "target PC.")


if __name__ == "__main__":
    main()
