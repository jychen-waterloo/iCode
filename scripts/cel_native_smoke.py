#!/usr/bin/env python3
"""Actual CEL 0.1.3 C++ extension smoke test in the installed runtime.

Executed by cibuildwheel inside the target manylinux2014 container, not with
mock CEL objects or a wheel filename check.
"""
from __future__ import annotations

import importlib.metadata
import platform
import sys
from pathlib import Path

from cel_expr_python import cel


def check() -> None:
    assert sys.version_info[:2] == (3, 14), sys.version
    version = importlib.metadata.version("cel-expr-python")
    assert version == "0.1.3", version
    extension = Path(cel.__file__).resolve()
    assert extension.is_file() and extension.suffix == ".so", extension
    env = cel.NewEnv(variables={
        "argv": cel.Type.List(cel.Type.STRING),
        "prefix": cel.Type.List(cel.Type.STRING),
    })
    yes = env.compile('argv == ["git", "status"]')
    no = env.compile('prefix.size() > 0 && prefix[0] == "rm"')
    assert yes.return_type() == cel.Type.BOOL
    assert no.return_type() == cel.Type.BOOL
    for argv, prefix, expected_allow, expected_block in [
        (["git", "status"], ["git", "status"], True, False),
        (["echo", "rm"], ["echo", "rm"], False, False),
        (["rm", "file"], ["rm", "file"], False, True),
        ([], [], False, False),
    ]:
        data = {"argv": argv, "prefix": prefix}
        assert yes.eval(data=data).value() is expected_allow
        assert no.eval(data=data).value() is expected_block
    # Runtime errors must not be converted into true; malformed expressions
    # and non-Boolean predicates must not pass the checked compilation stage.
    for expression in ('argv ==', '(argv[0]) && true', '1 + true'):
        try:
            env.compile(expression)
        except Exception:
            pass
        else:
            raise AssertionError(f"CEL accepted invalid expression: {expression}")

    libc, glibc = platform.libc_ver()
    print(
        f"CEL native smoke OK: {version} {extension} "
        f"CPython {sys.version.split()[0]} {platform.machine()} "
        f"{libc} {glibc}"
    )


if __name__ == "__main__":
    check()
