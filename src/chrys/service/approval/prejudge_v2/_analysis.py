# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Parser-independent representation for the shared shell policy matcher."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CommandNode:
    source_span: tuple[int, int]
    argv: tuple[str, ...] | None
    prefix: tuple[str, ...]
    text: str


@dataclass(frozen=True, slots=True)
class Analysis:
    syntax_valid: bool
    coverage_complete: bool
    executable_nodes: tuple[CommandNode, ...]
    unsupported: tuple[str, ...]
