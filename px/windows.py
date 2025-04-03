"Windows specific code"

import ctypes
import os
import sys
import winreg

from .debug import pprint, dprint
from . import config

try:
    import psutil
except ImportError:
    pprint("Requires module psutil")
    sys.exit(config.ERROR_IMPORT)

###
# Install Px to startup

def is_installed():
    "Check if Px is already installed in the Windows registry"
    runkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
    try:
        winreg.QueryValueEx(runkey, "Px")
    except FileNotFoundError:
        return False
    finally:
        winreg.CloseKey(runkey)
    return True

def install(script_cmd, pxini, force_overwrite):
    "Install Px to Windows registry if not already"
    if not is_installed() or force_overwrite:
        # Adjust cmd to run in the background
        cmd = script_cmd
        dirname, basename = os.path.split(cmd)
        if basename.lower() in ["px", "px.exe"]:
            cmd = os.path.join(dirname, "pxw.exe")
        if not os.path.exists(cmd):
            pprint(f"Cannot find {cmd}")
            sys.exit(config.ERROR_INSTALL)
        if " " in cmd:
            cmd = f'"{cmd}"'

        # Add --config to cmd
        if " " in pxini:
            cmd += f' "--config={pxini}"'
        else:
            cmd += f' --config={pxini}'

        # Write to registry
        runkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
            winreg.KEY_WRITE)
        winreg.SetValueEx(runkey, "Px", 0, winreg.REG_EXPAND_SZ, cmd)
        winreg.CloseKey(runkey)
        pprint("Px installed successfully")
    else:
        pprint("Px already installed")

    sys.exit(config.ERROR_SUCCESS)

def uninstall():
    "Uninstall Px from Windows registry if installed"
    if is_installed() is True:
        runkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
            winreg.KEY_WRITE)
        winreg.DeleteValue(runkey, "Px")
        winreg.CloseKey(runkey)
        pprint("Px uninstalled successfully")
    else:
        pprint("Px is not installed")

    sys.exit(config.ERROR_SUCCESS)

###
# Attach/detach console

def reopen_stdout(state):
    """Reopen stdout after attaching to the console"""

    clrstr = "\r" + " " * 80 + "\r"
    if state.debug is None:
        state.stdout = sys.stdout
        sys.stdout = open("CONOUT$", "w")
        sys.stdout.write(clrstr)
    else:
        state.stdout = state.debug.stdout
        state.debug.stdout = open("CONOUT$", "w")
        state.debug.stdout.write(clrstr)

def restore_stdout(state):
    """Restore stdout before detaching from the console"""

    if state.debug is None:
        sys.stdout.close()
        sys.stdout = state.stdout
    else:
        state.debug.stdout.close()
        state.debug.stdout = state.stdout

def attach_console(state):
    if ctypes.windll.kernel32.GetConsoleWindow() != 0:
        dprint("Already attached to a console")
        return

    # Find parent cmd.exe if exists
    process = psutil.Process()
    ppid_with_console = -1
    for par in process.parents():
        if os.path.basename(par.name()).lower() in [
                "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"]:
            # Found it
            ppid_with_console = par.pid
            break

    # Not found, started without console
    if ppid_with_console == -1:
        dprint("No parent console to attach to")
        return

    dprint("Attaching to console " + str(ppid_with_console))
    if ctypes.windll.kernel32.AttachConsole(ppid_with_console) == 0:
        dprint("Attach failed with error " +
            str(ctypes.windll.kernel32.GetLastError()))
        return

    if ctypes.windll.kernel32.GetConsoleWindow() == 0:
        dprint("Not a console window")
        return

    reopen_stdout(state)

def detach_console(state):
    if ctypes.windll.kernel32.GetConsoleWindow() == 0:
        return

    restore_stdout(state)

    if not ctypes.windll.kernel32.FreeConsole():
        dprint("Free console failed with error " +
            str(ctypes.windll.kernel32.GetLastError()))
    else:
        dprint("Freed console successfully")
