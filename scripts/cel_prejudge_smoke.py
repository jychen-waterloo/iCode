#!/usr/bin/env python3
"""Smoke test real iCode Pre-Judge with built CEL and Tree-sitter in old glibc.

Do not execute the example shell commands; inspect/route them only. This file
runs inside the manylinux2014 target container with the actual native wheels.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from prejudge_under_test import Route, analyze, load_policy, route

CONFIG = """schema_version: 1
mode: "enforce"
policy_id: smoke-v1
rules:
  - id: block-rm
    effect: block
    target: command
    when: 'prefix.size() > 0 && prefix[0] == "rm"'
  - id: allow-status
    effect: allow
    target: command
    when: 'argv == ["git", "status"]'
  - id: allow-echo
    effect: allow
    target: command
    when: 'argv.size() > 0 && argv[0] == "echo"'
"""


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "prejudge.yaml"
        path.write_text(CONFIG, encoding="utf-8")
        policy = load_policy(path)
    assert policy.mode == "enforce"
    cases = [
        ("git status", Route.ALLOW),
        ("rm fixture", Route.BLOCK),
        ('echo "rm"', Route.ALLOW),
        ("git status && rm fixture", Route.BLOCK),
        ("git status && unknown_tool", Route.DEFER),
        ('echo "$(rm fixture)"', Route.BLOCK),
        ('rm "$TARGET"', Route.BLOCK),
        ("git status > out.txt", Route.DEFER),
    ]
    for command, expected in cases:
        result = route(command, "bash", policy)
        assert result.route is expected, (command, expected, result)
    analysis = analyze("git status && echo ok", dialect="bash")
    assert analysis.syntax_valid and analysis.coverage_complete
    assert [tuple(n.argv or ()) for n in analysis.executable_nodes] == [
        ("git", "status"), ("echo", "ok")
    ]
    assert analyze("git status", dialect="zsh").unsupported == ("unsupported_dialect",)
    print(f"Pre-Judge native AST/CEL smoke passed {len(cases)} decisions.")


if __name__ == "__main__":
    main()
