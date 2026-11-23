# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Bind a certified call to one isolated launch of its configured shell."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from base64 import b64encode
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from chrys.foundation.platform.runtime_paths import build_shell_subprocess_env
from chrys.service.approval.prejudge_v2._powershell_paths import has_custom_module_configuration, module_locations
from chrys.service.approval.prejudge_v2._windows_paths import is_windows_namespace_path

if TYPE_CHECKING:
    from chrys.foundation.platform import ShellInfo

_BASH_DIALECTS = frozenset({"bash", "git_bash"})
_POWERSHELL_DIALECTS = frozenset({"powershell", "pwsh"})
_POWERSHELL_ISOLATED_ARGS = ("-NoProfile", "-NonInteractive", "-EncodedCommand")
_WINDOWS_COMMAND_LINE_LIMIT = 32_767  # UTF-16 code units including the terminating NUL.
_POWERSHELL_UTF8_PREAMBLE = "\n".join(
    (
        "$__chrysUtf8 = [System.Text.UTF8Encoding]::new($false)",
        "try {",
        "  [Console]::InputEncoding = $__chrysUtf8",
        "  [Console]::OutputEncoding = $__chrysUtf8",
        "} catch { }",
        "$OutputEncoding = $__chrysUtf8",
    )
)


class ApprovalInvalidatedError(PermissionError):
    """The approved shell call no longer matches the intended launch."""


def powershell_pipe_source(source: str) -> str:
    return f"{_POWERSHELL_UTF8_PREAMBLE}\n{source}"


def powershell_isolated_invocation(source: str, *, pipe: bool) -> tuple[tuple[str, ...], str]:
    script = powershell_pipe_source(source) if pipe else source
    return _POWERSHELL_ISOLATED_ARGS, b64encode(script.encode("utf-16-le")).decode("ascii")


def exceeds_isolated_launch_limit(shell: ShellInfo, source: str) -> bool:
    if sys.platform != "win32" or shell.name not in _POWERSHELL_DIALECTS:
        return False
    flags, payload = powershell_isolated_invocation(source, pipe=True)
    command_line = subprocess.list2cmdline((shell.path, *flags, payload))
    return len(command_line.encode("utf-16-le")) // 2 + 1 > _WINDOWS_COMMAND_LINE_LIMIT


def _trusted_locations(locations: tuple[str, ...], roots: tuple[str, ...]) -> bool:
    """Defer relative lookup and paths which the workspace can modify."""
    try:
        if sys.platform == "win32" and any(is_windows_namespace_path(path) for path in (*locations, *roots)):
            return False
        workspace = [(Path(root).absolute(), Path(root).resolve()) for root in roots]
        for location in locations:
            path = Path(location)
            if not path.is_absolute():
                return False
            resolved = path.resolve() if workspace else path
            if any(
                path.is_relative_to(lexical_root) or resolved.is_relative_to(resolved_root)
                for lexical_root, resolved_root in workspace
            ):
                return False
        return True
    except OSError, ValueError, RuntimeError:
        return False


def _trusted_lookup(env: dict[str, str], executables: tuple[str, ...], roots: tuple[str, ...]) -> bool:
    if not roots:
        return True
    directories = env.get("PATH", "").split(os.pathsep)
    try:
        links = []
        for word in set(executables):
            if "/" in word or "\\" in word:
                continue
            names = (word, word + ".exe") if os.name == "nt" else (word,)
            for directory in directories:
                for name in names:
                    candidate = Path(directory) / name
                    if candidate.is_symlink():
                        links.append(str(candidate))
        return _trusted_locations(tuple(links), roots)
    except OSError, ValueError:
        return False


def _powershell_applications(env: dict[str, str], executables: tuple[str, ...]) -> tuple[str, ...] | None:
    """Require native commands to resolve before PowerShell can try module discovery."""
    applications = []
    directories = env.get("PATH", "").split(os.pathsep)
    try:
        for word in dict.fromkeys(executables):
            if not word.lower().endswith(".exe"):
                continue
            candidates = [Path(word)] if "/" in word or "\\" in word else [Path(d) / word for d in directories]
            for path in candidates:
                if path.is_file() and os.access(path, os.X_OK):
                    applications.append(str(path.resolve(strict=True)))
                    break
            else:
                return None
    except OSError, ValueError, RuntimeError:
        return None
    return tuple(applications)


def _trusted_module_locations(shell: ShellInfo, env: dict[str, str], roots: tuple[str, ...]) -> bool:
    try:
        prepared = module_locations(shell, env)
        if prepared is None:
            return False
        locations, configs = prepared
        return _trusted_locations((*locations, *(str(config) for config in configs)), roots) and not any(
            has_custom_module_configuration(path) for path in configs
        )
    except OSError, RuntimeError, ValueError:
        return False


@dataclass(slots=True)
class ApprovedShell:
    dialect: str
    source: str
    owner: asyncio.Task[Any]
    environment: dict[str, str] = field(default_factory=dict)
    locations: tuple[str, ...] = ()
    roots: tuple[str, ...] = ()
    executables: tuple[str, ...] = ()
    native_applications: tuple[str, ...] = ()
    shell_path: str = ""
    shell_args: tuple[str, ...] = ()
    active: bool = True
    claimed: bool = False
    issued: bool = False

    def _matches(self, shell: ShellInfo, source: str) -> bool:
        return (
            self.active
            and asyncio.current_task() is self.owner
            and (self.dialect, self.source) == (shell.name, source)
            and (self.shell_path, self.shell_args) == (shell.path, tuple(shell.args))
        )

    def claim(self, shell: ShellInfo, source: str) -> bool:
        if self.claimed or not self._matches(shell, source):
            return False
        self.claimed = True
        return True

    def require_launch(self, shell: ShellInfo, source: str) -> None:
        if (
            not self.claimed
            or self.issued
            or not self._matches(shell, source)
            or not _trusted_locations(self.locations, self.roots)
            or not _trusted_lookup(self.environment, self.executables, self.roots)
        ):
            raise ApprovalInvalidatedError("The structured approval no longer binds this shell launch.")
        if shell.name in _POWERSHELL_DIALECTS and (
            not _trusted_module_locations(shell, self.environment, self.roots)
            or _powershell_applications(self.environment, self.executables) != self.native_applications
        ):
            raise ApprovalInvalidatedError("PowerShell launch trust changed after structured approval.")
        self.issued = True


def prepare_shell(
    shell: ShellInfo, source: str, executables: tuple[str, ...], roots: tuple[str, ...]
) -> ApprovedShell | None:
    """Compute shared Shadow and Enforce eligibility without running a shell."""
    owner = asyncio.current_task()
    if owner is None or not supports_isolated_launch(shell) or exceeds_isolated_launch_limit(shell, source):
        return None
    env = build_shell_subprocess_env()
    dialect = shell.name
    powershell = dialect in _POWERSHELL_DIALECTS
    locations = (
        shell.path,
        *env.get("PATH", "").split(os.pathsep),
        *(
            word
            for word in executables
            if (not powershell or word.lower().endswith(".exe")) and ("/" in word or "\\" in word)
        ),
    )
    if not _trusted_locations(locations, roots) or not _trusted_lookup(env, executables, roots):
        return None
    if powershell and not _trusted_module_locations(shell, env, roots):
        return None
    native = _powershell_applications(env, executables) if powershell else ()
    if native is None or not _trusted_locations(native, roots):
        return None
    if dialect in _BASH_DIALECTS:
        for key in tuple(env):
            if key in {"BASH_ENV", "ENV"} or key.startswith("BASH_FUNC_"):
                del env[key]
    return ApprovedShell(
        shell.name,
        source,
        owner,
        env,
        (*locations, *native),
        roots,
        executables,
        native_applications=native,
        shell_path=shell.path,
        shell_args=tuple(shell.args),
    )


def supports_isolated_launch(shell: ShellInfo) -> bool:
    if shell.name in _POWERSHELL_DIALECTS:
        return shell.args in (["-NoProfile", "-Command"], ["-Command"], ["-c"])
    return shell.name in _BASH_DIALECTS | {"zsh"} and shell.args == ["-c"]


isolated_shell_call: ContextVar[ApprovedShell | None] = ContextVar("prejudge_isolated_shell_call", default=None)
