# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Run the actual Bash grammar when the optional feature is installed."""
from __future__ import annotations

import pytest

from chrys.service.approval.prejudge_v2 import analyze

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_bash")


@pytest.mark.parametrize("cmd", [
    "git status",
    "git status && echo ok",
    "git status | wc -l",
    "git status; echo ok",
    "git 'status'",
    "g''it status",
    "{ git status; echo ok; }",
    "(git status; echo ok)",
])
def test_real_ast_never_mistakes_unknown_syntax_for_full_coverage(cmd):
    result = analyze(cmd, dialect="bash")
    assert result.syntax_valid
    assert result.executable_nodes or not result.coverage_complete


@pytest.mark.parametrize("cmd", [
    "rm -rf fixture 2>/dev/null",
    "FOO=1 rm fixture",
    "if true; then rm fixture; fi",
    "echo $(rm fixture)",
    "rm \"$TARGET\"",
    "git status > out.txt",
    "{rm,-rf,fixture}",
    "r? fixture",
])
def test_unsupported_commands_cannot_be_fully_allowed(cmd):
    result = analyze(cmd, dialect="bash")
    assert not result.coverage_complete


@pytest.mark.parametrize("dialect", ["zsh", "pwsh", "cmd", "dash"])
def test_unsupported_shell_dialect_is_explicit_defer(dialect):
    result = analyze("git status", dialect=dialect)
    assert "unsupported_dialect" in result.unsupported
    assert not result.coverage_complete
