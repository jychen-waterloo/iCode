# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Bind approved new-dialect text to the shell launch without user startup files."""

from __future__ import annotations

from contextvars import ContextVar

isolated_shell_call: ContextVar[tuple[str, str] | None] = ContextVar("prejudge_isolated_shell_call", default=None)
