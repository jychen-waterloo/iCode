# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Bind a certified call to one isolated launch of its configured shell."""

from __future__ import annotations

import asyncio
import os
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chrys.foundation.platform.runtime_paths import build_shell_subprocess_env

_BASH_DIALECTS = frozenset({"bash", "git_bash"})
_POWERSHELL_DIALECTS = frozenset({"powershell", "pwsh"})


class ApprovalInvalidatedError(PermissionError):
    """The approved shell call no longer matches the intended launch."""


def _trusted_locations(locations: tuple[str, ...], roots: tuple[str, ...]) -> bool:
    """Defer relative lookup and paths which the workspace can modify."""
    try:
        workspace = [Path(root).resolve() for root in roots]
        return all(
            Path(location).is_absolute()
            and not any(Path(location).resolve().is_relative_to(root) for root in workspace)
            for location in locations
        )
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
    active: bool = True
    claimed: bool = False
    issued: bool = False

    def _matches(self, dialect: str, source: str) -> bool:
        return self.active and asyncio.current_task() is self.owner and (self.dialect, self.source) == (dialect, source)

    def claim(self, dialect: str, source: str) -> bool:
        if self.claimed or not self._matches(dialect, source):
            return False
        self.claimed = True
        return True

    def require_launch(self, dialect: str, source: str) -> None:
        if (
            not self.claimed
            or self.issued
            or not self._matches(dialect, source)
            or not _trusted_locations(self.locations, self.roots)
            or not _trusted_lookup(self.environment, self.executables, self.roots)
        ):
            raise ApprovalInvalidatedError("The structured approval no longer binds this shell launch.")
        if dialect in _POWERSHELL_DIALECTS and (
            _powershell_applications(self.environment, self.executables) != self.native_applications
        ):
            raise ApprovalInvalidatedError("PowerShell executable resolution changed after structured approval.")
        self.issued = True


def prepare_shell(
    dialect: str, source: str, executables: tuple[str, ...], roots: tuple[str, ...]
) -> ApprovedShell | None:
    """Compute shared Shadow and Enforce eligibility without running a shell."""
    owner = asyncio.current_task()
    if owner is None or dialect not in _BASH_DIALECTS | _POWERSHELL_DIALECTS | {"zsh"}:
        return None
    env = build_shell_subprocess_env()
    powershell = dialect in _POWERSHELL_DIALECTS
    native = _powershell_applications(env, executables) if powershell else ()
    if native is None:
        return None
    module_path = env.get("PSMODULEPATH" if os.name == "nt" else "PSModulePath")
    locations = (
        *env.get("PATH", "").split(os.pathsep),
        *(module_path.split(os.pathsep) if powershell and module_path is not None else ()),
        *native,
        *(word for word in executables if not powershell and ("/" in word or "\\" in word)),
    )
    if not _trusted_locations(locations, roots) or not _trusted_lookup(env, executables, roots):
        return None
    if dialect in _BASH_DIALECTS:
        for key in tuple(env):
            if key in {"BASH_ENV", "ENV"} or key.startswith("BASH_FUNC_"):
                del env[key]
    return ApprovedShell(dialect, source, owner, env, locations, roots, executables, native)


isolated_shell_call: ContextVar[ApprovedShell | None] = ContextVar("prejudge_isolated_shell_call", default=None)
