# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Carry a confirmed file destination across async middleware and worker threads."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from chrys.foundation.platform.paths import resolve_workspace_path

_approved_targets: ContextVar[tuple[str, ...] | None] = ContextVar("approved_file_targets", default=None)


def file_write_target(path: str, *, base_cwd: str | None = None) -> str:
    """Resolve directory links, allowing new files but rejecting unresolvable paths."""
    lexical = resolve_workspace_path(path, base_cwd=base_cwd)
    # Atomic replacement replaces a final symlink itself, while edit previews
    # read its referent. Keep this mixed operation on ordinary approval.
    if os.path.islink(lexical):
        raise ValueError("A final symbolic link is not a reusable file destination.")
    return os.path.realpath(lexical, strict=os.path.ALLOW_MISSING)


@contextmanager
def approved_file_targets(targets: tuple[str, ...] | None) -> Iterator[None]:
    token = _approved_targets.set(targets)
    try:
        yield
    finally:
        _approved_targets.reset(token)


def approved_write_path(path: str, *, base_cwd: str | None = None) -> str:
    """Check at the write boundary and pin the path used by the whole operation."""
    targets = _approved_targets.get()
    if targets is None:
        return path
    target = file_write_target(path, base_cwd=base_cwd)
    if target not in targets:
        raise ValueError("File destination changed after approval; request approval again.")
    return target
