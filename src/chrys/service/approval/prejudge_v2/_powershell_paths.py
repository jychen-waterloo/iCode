# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Locate module search paths added by PowerShell itself at startup."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from stat import S_ISREG
from typing import TYPE_CHECKING

from chrys.service.approval.prejudge_v2._windows_paths import is_windows_namespace_path

if TYPE_CHECKING:
    from chrys.foundation.platform import ShellInfo


def _windows_documents() -> str:
    if sys.platform != "win32":
        return ""
    from ctypes import create_unicode_buffer, windll

    buffer = create_unicode_buffer(260)
    # CSIDL_PERSONAL | CSIDL_FLAG_DONT_VERIFY returns the current, possibly
    # redirected Documents location without opening the directory.
    result = windll.shell32.SHGetFolderPathW(None, 0x4005, None, 0, buffer)
    return buffer.value if result == 0 else ""


def _windows_registered_paths() -> tuple[str, ...]:
    if sys.platform != "win32":
        return ()
    import winreg

    paths = []
    for hive, key in (
        (winreg.HKEY_CURRENT_USER, "Environment"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
    ):
        try:
            with winreg.OpenKey(hive, key) as handle:
                value, kind = winreg.QueryValueEx(handle, "PSModulePath")
        except FileNotFoundError:
            continue
        if not isinstance(value, str):
            raise ValueError("Unsupported Windows PSModulePath value")
        if kind == winreg.REG_EXPAND_SZ:
            value = winreg.ExpandEnvironmentStrings(value)
        if value:
            paths.extend(value.split(";"))
    return tuple(paths)


def module_locations(shell: ShellInfo, env: dict[str, str]) -> tuple[tuple[str, ...], tuple[Path, ...]] | None:
    """Overapproximate startup lookup, deferring when it cannot be certified."""
    installation = Path(shell.path).resolve().parent
    inherited = env.get("PSMODULEPATH" if sys.platform == "win32" else "PSModulePath")
    locations = [str(installation / "Modules"), *(inherited.split(os.pathsep) if inherited else ())]
    if sys.platform == "win32":
        documents = _windows_documents()
        program_files = env.get("PROGRAMFILES")
        profile = env.get("USERPROFILE")
        system_root = env.get("SYSTEMROOT")
        if not documents or not program_files or not profile or not system_root or is_windows_namespace_path(documents):
            return None
        # A missing Documents directory can produce a relative module path.
        if not Path(documents).is_dir():
            return None
        edition = "WindowsPowerShell" if shell.name == "powershell" else "PowerShell"
        # A fresh process can see the profile default even when the parent's
        # known-folder lookup is cached or the folder is redirected.
        user_dirs = (Path(documents) / edition, Path(profile) / "Documents" / edition)
        locations.extend(str(path / "Modules") for path in (*user_dirs, Path(program_files) / edition))
        # PowerShell 7 can append legacy machine locations on Windows.
        locations.extend(
            (
                str(Path(program_files) / "WindowsPowerShell" / "Modules"),
                str(Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "Modules"),
            )
        )
        locations.extend(_windows_registered_paths())
    else:
        home = Path(env["HOME"]) if env.get("HOME") else Path.home()
        data = Path(env["XDG_DATA_HOME"]) if env.get("XDG_DATA_HOME") else home / ".local" / "share"
        config = Path(env["XDG_CONFIG_HOME"]) if env.get("XDG_CONFIG_HOME") else home / ".config"
        user_dirs = (config / "powershell",)
        locations.extend((str(data / "powershell" / "Modules"), "/usr/local/share/powershell/Modules"))
    configs = (
        tuple(dict.fromkeys(path / "powershell.config.json" for path in (installation, *user_dirs)))
        if shell.name == "pwsh"
        else ()
    )
    return tuple(locations), configs


def has_custom_module_configuration(path: Path) -> bool:
    """Leave custom lookup overrides to the ordinary shell."""
    try:
        stat = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return False
    if stat.st_size > 64 * 1024 or not S_ISREG(stat.st_mode):
        return True
    with path.open(encoding="utf-8-sig") as stream:
        contents = json.loads(stream.read(64 * 1024 + 1))
    return not isinstance(contents, dict) or any(key.casefold() == "psmodulepath" for key in contents)
