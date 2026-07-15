"""
datychö — single entry point for every mode.

Usage (packaged datycho.exe or `python datycho.py`):
    datycho.exe                 -> GUI setup wizard (default; needs admin)
    datycho.exe agent ...       -> GUI agent in the user session (spawned by service)
    datycho.exe uninstall       -> GUI uninstaller (needs admin)
    datycho.exe --service-run   -> service host (launched by the Windows SCM)

The default (no arguments) opens the installer wizard, so double-clicking the
exe just works for a parent.
"""

import os
import sys


def main():
    args = sys.argv[1:]
    mode = args[0] if args else ""

    if mode == "--selftest":
        # Headless check that every module imports inside the frozen bundle.
        # Uses os._exit so a --windowed build never pops an error dialog.
        try:
            import common, branding, service, agent, installer_gui  # noqa: F401
        except Exception:
            os._exit(2)
        os._exit(0)

    if mode == "--service-run":
        import service
        service.run_service_dispatch()
        return

    if mode == "agent":
        import agent
        agent.main(args[1:])
        return

    if mode == "uninstall":
        import installer_gui
        installer_gui.run_uninstall()
        return

    if mode == "install" or mode == "":
        import installer_gui
        installer_gui.run_install()
        return

    # Anything else: fall back to pywin32's service command handler so
    # `datycho.py install/start/stop/remove` still works during development.
    import service
    import win32serviceutil
    win32serviceutil.HandleCommandLine(service.DatychoService)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        # Never surface a raw crash dialog to the child; log instead.
        try:
            import common
            common.setup_logger("datycho").exception("Unhandled error")
        except Exception:
            pass
        os._exit(1)
