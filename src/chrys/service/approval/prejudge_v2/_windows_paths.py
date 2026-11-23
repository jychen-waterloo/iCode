# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Classify decoded paths for Windows shell approval."""

from __future__ import annotations

import re

_PROVIDER_PREFIX = re.compile(r"^[^:/\\]{2,}:")


def is_windows_namespace_path(value: str) -> bool:
    value = value.lstrip()
    return len(value) >= 2 and value[0] in "\\/" and value[1] in "\\/"


def unsafe_argument_reason(argv: tuple[str, ...], dialect: str) -> str | None:
    powershell = dialect in {"powershell", "pwsh"}
    if not powershell and dialect != "git_bash":
        return None
    for arg in argv:
        # Native options can carry a path in the same argument.
        value = arg.partition("=")[2] if arg.startswith("-") else ""
        for candidate in (arg, value):
            if is_windows_namespace_path(candidate):
                return "windows_namespace_path"
            if powershell and ("::" in candidate or _PROVIDER_PREFIX.match(candidate.lstrip())):
                return "powershell_provider_path"
    return None
