# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Exercise the pinned Zsh and PowerShell grammars and the shared policy."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys

import pytest

from chrys.foundation.platform import ShellInfo
from chrys.foundation.platform.process import windows_hidden_subprocess_kwargs
from chrys.service.approval.prejudge_v2 import Matcher, Policy, Route, Rule, analyze, load_policy, route
from chrys.service.approval.prejudge_v2.execution import isolated_shell_call
from chrys.service.tools.builtins.shell import _shell_argv_variants

_GRAMMARS = ("tree_sitter", "tree_sitter_zsh", "tree_sitter_pwsh")
_PS_DIALECTS = ("powershell", "pwsh")
_PS_EXE = "C:/Windows/System32/whoami.exe"
_PWSH_EXES = (
    (_PS_EXE, "C:/Windows/System32/findstr.exe") if sys.platform == "win32" else ("/usr/bin/printf", "/usr/bin/head")
)
_ZSH_EXE = "/usr/bin/printf"

if os.environ.get("CI") and any(importlib.util.find_spec(name) is None for name in _GRAMMARS):
    raise RuntimeError("CI requires the pinned Zsh and PowerShell Tree-sitter grammars")
for _grammar in _GRAMMARS:
    pytest.importorskip(_grammar)


@pytest.mark.parametrize(
    ("command", "argv"),
    [
        ("git status", (("git", "status"),)),
        ("git 'status'", (("git", "status"),)),
        ('cat "file name.txt"', (("cat", "file name.txt"),)),
        ("git status | head -10", (("git", "status"), ("head", "-10"))),
        ("git status; cat README.md\nhead -10", (("git", "status"), ("cat", "README.md"), ("head", "-10"))),
    ],
)
def test_zsh_static_argv(command, argv):
    analysis = analyze(command, dialect="zsh")
    assert analysis.syntax_valid and analysis.coverage_complete
    assert tuple(node.argv for node in analysis.executable_nodes) == argv


@pytest.mark.parametrize("dialect", _PS_DIALECTS)
@pytest.mark.parametrize(
    ("command", "argv"),
    [
        ("Get-Content README.md", (("Get-Content", "README.md"),)),
        ("Get-Content -LiteralPath README.md", (("Get-Content", "-LiteralPath", "README.md"),)),
        ('Get-Content -Path "file name.txt"', (("Get-Content", "-Path", "file name.txt"),)),
        ("Get-ChildItem .", (("Get-ChildItem", "."),)),
        ("git status", (("git", "status"),)),
        ("Write-Output 'it''s'", (("Write-Output", "it's"),)),
        ('Write-Output "say ""hi"""', (("Write-Output", 'say "hi"'),)),
        (
            "Get-Content README.md | Select-Object -First 10",
            (("Get-Content", "README.md"), ("Select-Object", "-First", "10")),
        ),
        ("Write-Output first\r\nWrite-Output second", (("Write-Output", "first"), ("Write-Output", "second"))),
    ],
)
def test_powershell_static_argv(dialect, command, argv):
    analysis = analyze(command, dialect=dialect)
    assert analysis.syntax_valid and analysis.coverage_complete
    assert tuple(node.argv for node in analysis.executable_nodes) == argv


@pytest.mark.parametrize(
    ("dialect", "head", "other"),
    [
        ("bash", "printf", "head"),
        ("git_bash", "printf", "head"),
        ("zsh", _ZSH_EXE, "/usr/bin/head"),
        ("powershell", _PS_EXE, "C:/Windows/System32/findstr.exe"),
        ("pwsh", *_PWSH_EXES),
    ],
)
def test_real_dialects_share_the_same_yaml_rules(tmp_path, dialect, head, other):
    config = tmp_path / "prejudge.yaml"
    config.write_text(
        "schema_version: 1\nmode: enforce\npolicy_id: portable\nrules:\n"
        f"  - id: first\n    effect: allow\n    target: command\n    match: {{argv_exact: ['{head}', hello]}}\n"
        f"  - id: second\n    effect: allow\n    target: command\n    match: {{argv_first: ['{other}']}}\n",
        encoding="utf-8",
    )
    policy = load_policy(config)
    for separator in (" | ", "; ", "\n"):
        command = f"{head} 'hello'{separator}{other} hello"
        decision = route(command, dialect, policy)
        assert decision.route is Route.ALLOW
        assert decision.matched_rule_ids == ("first", "second")
        assert len(decision.matched_node_spans) == 2
    assert route(f"{head} 'different' | {other} hello", dialect, policy).route is Route.DEFER


@pytest.mark.parametrize(
    "command",
    [
        '"/usr/bin/printf" hello',
        '/usr/bin/printf "$HOME"',
        '/usr/bin/printf "$(printf hello)"',
        "/usr/bin/printf <(printf hello)",
        "/usr/bin/printf *.txt",
        "/usr/bin/printf file(.N)",
        "/usr/bin/printf file#",
        "/usr/bin/printf !previous",
        "/usr/bin/printf {left,right}",
        '/usr/bin/printf "${items[@]}"',
        "/usr/bin/printf hello > output.txt",
        "FOO=bar /usr/bin/printf hello",
        "command /usr/bin/printf hello",
        "function sample() { /usr/bin/printf hello; }; sample",
        "/usr/bin/printf hello |& /usr/bin/printf world",
        "/usr/bin/printf 'unterminated",
        "/usr/bin/printf hello\x00",
        "/usr/bin/printf\u00a0hello",
    ],
)
def test_zsh_unknown_or_dynamic_defers(command):
    policy = Policy("enforce", "zsh", (Rule("printf", Route.ALLOW, Matcher("argv_first", (_ZSH_EXE,))),))
    assert route(command, "zsh", policy).route is Route.DEFER


@pytest.mark.parametrize("dialect", _PS_DIALECTS)
@pytest.mark.parametrize(
    "source",
    [
        "{exe} $env:PATH",
        "{exe} $(Write-Output sample)",
        "{exe} @args",
        '{exe} "value $env:NAME"',
        "{exe} {{ Write-Output sample }}",
        "{exe} hello > output.txt",
        "{exe} hello; Get-Content README.md",
        "& $command",
        "& '{exe}' hello",
        ". ./fixture.ps1",
        "Invoke-Expression $cmd",
        "{exe} first,second",
        "{exe} --% hello",
        "{exe} -Mode:hello",
        "{exe} 0x20",
        "{exe} hello`\nworld",
        "{exe} 'unterminated",
        "{exe} hello && {exe} world",
    ],
)
def test_powershell_unknown_or_dynamic_defers(dialect, source):
    exe = _PS_EXE if dialect == "powershell" or sys.platform == "win32" else "/usr/bin/printf"
    policy = Policy("enforce", "ps", (Rule("native", Route.ALLOW, Matcher("argv_first", (exe,))),))
    assert route(source.format(exe=exe), dialect, policy).route is Route.DEFER


@pytest.mark.parametrize(
    ("dialect", "head", "argument"),
    [
        ("zsh", "git", "status"),
        ("powershell", "Get-Content", "README.md"),
        ("pwsh", "gEt-CoNtEnT", "README.md"),
        ("pwsh", "gc", "README.md"),
    ],
)
def test_a_matching_rule_cannot_resolve_a_bare_name(dialect, head, argument):
    policy = Policy("enforce", "identity", (Rule("exact", Route.ALLOW, Matcher("argv_exact", (head, argument))),))
    decision = route(f"{head} {argument}", dialect, policy)
    assert decision.route is Route.DEFER
    assert decision.reason_code == "unresolved_executable"
    assert decision.matched_rule_ids == ("exact",)


def test_missing_optional_grammar_defers_instead_of_matching(monkeypatch):
    from chrys.service.approval.prejudge_v2 import _adapters

    monkeypatch.setattr(_adapters, "_language", lambda _name: None)
    policy = Policy("enforce", "missing", (Rule("exact", Route.ALLOW, Matcher("argv_exact", (_ZSH_EXE, "hello"))),))
    decision = route(f"{_ZSH_EXE} hello", "zsh", policy)
    assert decision.route is Route.DEFER
    assert decision.reason_code == "grammar_unavailable"


_PS_ORACLE = """
$tokens = $null
$errors = $null
$root = [System.Management.Automation.Language.Parser]::ParseInput(
    $env:ICODE_TEST_POWERSHELL_SOURCE, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw ($errors -join '; ') }
$commands = @(
    foreach ($command in $root.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true)) {
        ,@(
            foreach ($element in $command.CommandElements) {
                if ($element -is [System.Management.Automation.Language.CommandParameterAst]) {
                    $element.Extent.Text
                } else {
                    [string] $element.Value
                }
            }
        )
    }
)
ConvertTo-Json -InputObject $commands -Compress
"""


@pytest.mark.parametrize("dialect", _PS_DIALECTS)
def test_microsoft_parser_agrees_on_native_cst_subset(dialect, tmp_path):
    executable = shutil.which(dialect)
    if not executable:
        if os.environ.get("CI") and sys.platform == "win32":
            pytest.fail(f"Windows CI requires {dialect} for the native parser oracle")
        pytest.skip(f"{dialect} is unavailable on this host")
    command = 'Get-Content -LiteralPath \'a b.txt\' | Select-Object -First 10; Write-Output "say ""hello"""'
    analysis = analyze(command, dialect=dialect)
    assert analysis.coverage_complete
    parsed = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-Command", _PS_ORACLE],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
        env={
            **os.environ,
            "HOME": str(tmp_path),
            "USERPROFILE": str(tmp_path),
            "APPDATA": str(tmp_path),
            "ICODE_TEST_POWERSHELL_SOURCE": command,
        },
        **windows_hidden_subprocess_kwargs(),
    )
    assert [list(node.argv or ()) for node in analysis.executable_nodes] == json.loads(parsed.stdout)


def test_native_zsh_launch_skips_user_startup_for_the_approved_text(tmp_path):
    executable = shutil.which("zsh")
    if not executable or sys.platform == "win32":
        if os.environ.get("CI") and sys.platform == "darwin":
            pytest.fail("macOS CI requires zsh for the native startup test")
        pytest.skip("native POSIX zsh is unavailable on this host")
    (tmp_path / ".zshenv").write_text("alias -g token=changed\n", encoding="utf-8")
    command = "/usr/bin/printf '%s' token | /usr/bin/head -1"
    policy = Policy(
        "enforce",
        "native",
        (
            Rule("print", Route.ALLOW, Matcher("argv_exact", ("/usr/bin/printf", "%s", "token"))),
            Rule("head", Route.ALLOW, Matcher("argv_exact", ("/usr/bin/head", "-1"))),
        ),
    )
    assert route(command, "zsh", policy).route is Route.ALLOW
    shell = ShellInfo(name="zsh", path=executable, args=["-c"])
    normal = _shell_argv_variants(shell, command)[0]
    token = isolated_shell_call.set(("zsh", command))
    try:
        approved = _shell_argv_variants(shell, command)[0]
    finally:
        isolated_shell_call.reset(token)
    env = {**os.environ, "HOME": str(tmp_path), "ZDOTDIR": str(tmp_path)}

    def output(argv: tuple[str, ...]) -> str:
        return subprocess.run(
            argv, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True, timeout=15
        ).stdout

    assert output(normal) == "changed"
    assert output(approved) == "token"
