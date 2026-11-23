# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Exercise the pinned Zsh and PowerShell grammars and the shared policy."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import pytest

from chrys.foundation.platform.process import windows_hidden_subprocess_kwargs
from chrys.service.approval.prejudge_v2 import Matcher, Policy, Route, Rule, analyze, load_policy, route
from tests.support.prejudge import require_grammars

_GRAMMARS = ("tree_sitter", "tree_sitter_zsh", "tree_sitter_pwsh")
_PS_DIALECTS = ("powershell", "pwsh")
_PS_EXE = "git.exe"
_PS_CHILD_ITEM = r"Microsoft.PowerShell.Management\Get-ChildItem"
_PS_WRITE_OUTPUT = r"Microsoft.PowerShell.Utility\Write-Output"
_ZSH_EXE = "/usr/bin/printf"

require_grammars(*_GRAMMARS)


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
        ("git.exe +5", (("git.exe", "+5"),)),
        (f"{_PS_CHILD_ITEM} -LiteralPath .", ((_PS_CHILD_ITEM, "-LiteralPath", "."),)),
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
        ("zsh", "printf", "head"),
        ("powershell", _PS_EXE, _PS_WRITE_OUTPUT),
        ("pwsh", _PS_EXE, _PS_WRITE_OUTPUT),
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
    ("dialect", "executable", "path"),
    [
        ("git_bash", "cat", "C:/fixture/path.txt"),
        ("powershell", _PS_CHILD_ITEM, r"C:\fixture\path.txt"),
        ("pwsh", _PS_CHILD_ITEM, r"c:\fixture\path.txt"),
        ("bash", "cat", "//fixture/local"),
        ("zsh", "cat", "//fixture/local"),
    ],
)
def test_local_path_arguments_remain_eligible(dialect, executable, path):
    rule = Rule("fixture", Route.ALLOW, Matcher("argv_first", (executable,)))
    decision = route(f"{executable} '{path}'", dialect, Policy("enforce", "fixture", (rule,)))
    assert decision.route is Route.ALLOW


def test_zsh_history_builtin_defers_under_matching_policy():
    rule = Rule("fixture", Route.ALLOW, Matcher("argv_first", ("fc",)))
    decision = route("fc -l", "zsh", Policy("enforce", "fixture", (rule,)))
    assert decision.route is Route.DEFER
    assert decision.reason_code == "unresolved_executable"


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
        "alias fixture=printf",
        "setopt SH_WORD_SPLIT",
        "autoload fixture",
    ],
)
def test_zsh_unknown_or_dynamic_defers(command):
    heads = {_ZSH_EXE, command.split()[0]}
    policy = Policy(
        "enforce",
        "zsh",
        tuple(Rule(head, Route.ALLOW, Matcher("argv_first", (head,))) for head in sorted(heads)),
    )
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
    exe = _PS_EXE
    policy = Policy("enforce", "ps", (Rule("native", Route.ALLOW, Matcher("argv_first", (exe,))),))
    assert route(source.format(exe=exe), dialect, policy).route is Route.DEFER


@pytest.mark.parametrize(
    ("dialect", "head", "argument"),
    [
        ("powershell", "Get-Content", "README.md"),
        ("pwsh", "gEt-CoNtEnT", "README.md"),
        ("pwsh", "gc", "README.md"),
        ("pwsh", "git", "status"),
        ("powershell", r"Microsoft.PowerShell.Management\gci", "."),
        ("pwsh", r"LocalFixtures\Get-ChildItem", "."),
    ],
)
def test_a_matching_rule_cannot_resolve_an_unapproved_powershell_name(dialect, head, argument):
    policy = Policy("enforce", "identity", (Rule("exact", Route.ALLOW, Matcher("argv_exact", (head, argument))),))
    decision = route(f"{head} {argument}", dialect, policy)
    assert decision.route is Route.DEFER
    assert decision.reason_code == "unresolved_executable"
    assert decision.matched_rule_ids == ("exact",)


@pytest.mark.parametrize("dialect", _PS_DIALECTS)
def test_qualified_powershell_policy_preserves_literal_case(dialect):
    policy = Policy(
        "enforce",
        "ps",
        (Rule("exact", Route.ALLOW, Matcher("argv_exact", (_PS_CHILD_ITEM, "-LiteralPath", "."))),),
    )
    assert route(f"{_PS_CHILD_ITEM} -LiteralPath .", dialect, policy).route is Route.ALLOW
    assert route(f"{_PS_CHILD_ITEM.lower()} -LiteralPath .", dialect, policy).route is Route.DEFER


@pytest.mark.parametrize("dialect", _PS_DIALECTS)
@pytest.mark.parametrize("argument", ["''", """'value "quoted"'""", r"'with spaces\'"])
def test_powershell_native_argument_binder_ambiguities_defer(dialect, argument):
    policy = Policy("enforce", "ps", (Rule("native", Route.ALLOW, Matcher("argv_first", (_PS_EXE,))),))
    assert route(f"{_PS_EXE} {argument}", dialect, policy).route is Route.DEFER


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
    command = (
        f'{_PS_CHILD_ITEM} -LiteralPath \'a b.txt\' | Select-Object -First 10; Write-Output "say ""hello"""; git.exe +5'
    )
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
    runtime_source = f"{_PS_WRITE_OUTPUT} 'two words'\r\n{_PS_WRITE_OUTPUT} 'next line'"
    runtime_analysis = analyze(runtime_source, dialect=dialect)
    assert runtime_analysis.coverage_complete
    result = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-Command", runtime_source],
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
        env={**os.environ, "HOME": str(tmp_path), "USERPROFILE": str(tmp_path), "APPDATA": str(tmp_path)},
        **windows_hidden_subprocess_kwargs(),
    )
    assert result.stdout.splitlines() == [node.argv[1] for node in runtime_analysis.executable_nodes if node.argv]


@pytest.mark.parametrize("dialect", _PS_DIALECTS)
def test_powershell_fresh_session_resolves_system_cmdlet_and_preserves_native_plus(dialect, tmp_path):
    executable = shutil.which(dialect)
    if not executable:
        if os.environ.get("CI") and sys.platform == "win32":
            pytest.fail(f"Windows CI requires {dialect} for the native argv test")
        pytest.skip(f"{dialect} is unavailable on this host")
    source = """
$ErrorActionPreference = 'Stop'
function Get-ChildItem { 'unqualified fixture' }
$command = Get-Command $env:ICODE_TEST_QUALIFIED_NAME
$moduleRoot = Join-Path $PSHOME Modules
if ($command.CommandType -ne 'Cmdlet' -or
    -not $command.Module.Path.StartsWith($moduleRoot + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Expected installed management cmdlet'
}
if ($env:ICODE_TEST_NATIVE_NAME) {
    $resolved = Get-Command $env:ICODE_TEST_NATIVE_NAME
    if ($resolved.CommandType -ne 'Application' -or $resolved.Source -ne $env:ICODE_TEST_PYTHON) {
        throw 'Expected a native executable from PATH'
    }
    Set-Alias -Name $env:ICODE_TEST_NATIVE_NAME -Value Get-ChildItem
    if ((Get-Command $env:ICODE_TEST_NATIVE_NAME).CommandType -ne 'Alias') {
        throw 'Expected the test alias to take priority in the modified session'
    }
}
& $env:ICODE_TEST_PYTHON -c 'import json,sys; print(json.dumps(sys.argv[1:]))' +5 '+5'
exit $LASTEXITCODE
"""
    result = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-Command", source],
        cwd=tmp_path,
        env={
            **os.environ,
            "HOME": str(tmp_path),
            "USERPROFILE": str(tmp_path),
            "APPDATA": str(tmp_path),
            "ICODE_TEST_PYTHON": sys.executable,
            "ICODE_TEST_NATIVE_NAME": os.path.basename(sys.executable) if sys.platform == "win32" else "",
            "ICODE_TEST_QUALIFIED_NAME": _PS_CHILD_ITEM.lower(),
            "PATH": os.pathsep.join((os.path.dirname(sys.executable), os.environ["PATH"])),
        },
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
        **windows_hidden_subprocess_kwargs(),
    )
    assert json.loads(result.stdout) == ["+5", "+5"]


def test_native_zsh_literal_argv_matches_the_certified_subset(tmp_path):
    executable = shutil.which("zsh")
    if not executable or sys.platform == "win32":
        if os.environ.get("CI") and sys.platform == "darwin":
            pytest.fail("macOS CI requires zsh for the native argv test")
        pytest.skip("native POSIX zsh is unavailable on this host")
    (tmp_path / ".zshenv").write_text(
        "alias printf='print -nr -- startup-alias'\nhead() { print -r -- startup-function; }\n",
        encoding="utf-8",
    )
    (tmp_path / "fixture.txt").write_text("ordinary-file\nnext line\n", encoding="utf-8")
    command = "printf\t'[%s]' 'two words' ''; head -n 1 fixture.txt"
    analysis = analyze(command, dialect="zsh")
    assert analysis.coverage_complete
    assert [node.argv for node in analysis.executable_nodes] == [
        ("printf", "[%s]", "two words", ""),
        ("head", "-n", "1", "fixture.txt"),
    ]
    normal = subprocess.run(
        [executable, "-c", command],
        env={**os.environ, "HOME": str(tmp_path), "ZDOTDIR": str(tmp_path)},
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    assert "startup-alias" in normal.stdout and "startup-function" in normal.stdout
    isolated = subprocess.run(
        [executable, "-f", "-d", "-o", "noaliases", "-c", command],
        env={**os.environ, "HOME": str(tmp_path), "ZDOTDIR": str(tmp_path)},
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    assert isolated.stdout == "[two words][]ordinary-file\n"
