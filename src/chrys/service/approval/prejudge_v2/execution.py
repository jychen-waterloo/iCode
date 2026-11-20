# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Bind a certified single command to a direct, trusted system executable."""

from __future__ import annotations

import asyncio
import os
import stat
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from chrys.foundation.platform import get_platform

_SYSTEM_DIRS = frozenset({Path("/bin"), Path("/usr/bin")})
_NATIVE_MAGIC = {
    b"\x7fELF",
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xca\xfe\xba\xbf",
}


def _trusted_system_executable(word: str) -> bool:
    """Allow only a nonmutable, link-free system binary under POSIX trust."""
    if get_platform().is_windows:
        return False
    path = Path(word)
    if path.parent not in _SYSTEM_DIRS or path.as_posix() != word:
        return False
    try:
        for component in (path, *path.parents):
            info = component.lstat()
            expected_type = stat.S_ISREG if component == path else stat.S_ISDIR
            if (
                not expected_type(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
                or os.access(component, os.W_OK)
            ):
                return False
        if not os.access(path, os.X_OK):
            return False
        with path.open("rb") as binary:
            return binary.read(4) in _NATIVE_MAGIC
    except OSError:
        return False


@dataclass(slots=True)
class ApprovedArgv:
    dialect: str
    source: str
    argv: tuple[str, ...]
    owner: asyncio.Task[Any]
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

    def for_launch(self, dialect: str, source: str) -> tuple[str, ...]:
        if (
            not self.claimed
            or self.issued
            or not self._matches(dialect, source)
            or not _trusted_system_executable(self.argv[0])
        ):
            raise PermissionError("The structured approval no longer binds a trusted executable.")
        self.issued = True
        return self.argv


def prepare_execution(dialect: str, source: str, argv: tuple[str, ...]) -> ApprovedArgv | None:
    if not argv or dialect not in {"bash", "zsh", "pwsh"} or not _trusted_system_executable(argv[0]):
        return None
    owner = asyncio.current_task()
    return ApprovedArgv(dialect, source, argv, owner) if owner is not None else None


isolated_shell_call: ContextVar[ApprovedArgv | None] = ContextVar("prejudge_isolated_shell_call", default=None)
