# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Shared user context for approval consumers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, runtime_checkable


@runtime_checkable
class TurnContextReader(Protocol):
    """Read-only view consumed by approval judges."""

    @property
    def user_message(self) -> str: ...

    @property
    def user_messages(self) -> list[str]: ...

    @property
    def compact_context(self) -> str: ...


class TurnContextHolder:
    """Mutable run-owned context shared by main and ACP approval paths."""

    def __init__(self, compact_context_provider: Callable[[], str] | None = None) -> None:
        self._messages: list[str] = []
        self._compact_context_provider = compact_context_provider

    @property
    def compact_context(self) -> str:
        """Read current summaries, including compaction during a running turn."""
        return self._compact_context_provider() if self._compact_context_provider is not None else ""

    @property
    def user_message(self) -> str:
        return self._messages[-1] if self._messages else ""

    @property
    def user_messages(self) -> list[str]:
        return list(self._messages)

    def replace(self, messages: list[str]) -> None:
        self._messages = [message for message in messages if message]

    def append(self, text: str) -> None:
        if text:
            self._messages.append(text)

    def remove(self, text: str) -> None:
        for index in range(len(self._messages) - 1, -1, -1):
            if self._messages[index] == text:
                del self._messages[index]
                break

    def reset(self) -> None:
        self._messages.clear()
