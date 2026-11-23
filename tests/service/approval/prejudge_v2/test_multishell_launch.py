# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Verify the real Zsh and PowerShell approval-to-shell boundary."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from chrys.foundation.events.bus import EventBus
from chrys.foundation.events.types import ApprovalRequest, ApprovalResponse
from chrys.foundation.models.session_env import SessionEnvironment
from chrys.foundation.platform import ShellInfo, get_platform
from chrys.foundation.platform.process import windows_hidden_subprocess_kwargs
from chrys.kernel.middleware import FunctionInvocationContext
from chrys.service.agent_middleware.control import approval as approval_module
from chrys.service.agent_middleware.control.approval import ApprovalMiddleware
from chrys.service.approval.policy import ApprovalMode, ApprovalPolicy
from chrys.service.approval.prejudge_v2 import Route, analyze, load_policy, route
from chrys.service.approval.prejudge_v2._powershell_paths import module_locations
from chrys.service.approval.prejudge_v2.execution import exceeds_isolated_launch_limit, powershell_isolated_invocation
from chrys.service.profiles.agents.schema import ApprovalConfig
from chrys.service.tools.builtins import shell as shell_module
from chrys.service.tools.builtins.shell import ShellTools
from tests.support.prejudge import require_grammars

require_grammars("tree_sitter", "tree_sitter_bash", "tree_sitter_zsh", "tree_sitter_pwsh")

_PS_DIALECTS = ("powershell", "pwsh")
_GET_CHILD_ITEM = r"Microsoft.PowerShell.Management\Get-ChildItem"
_GET_ITEM = r"Microsoft.PowerShell.Management\Get-Item"
_GET_CONTENT = r"Microsoft.PowerShell.Management\Get-Content"


def _shell(dialect):
    executable = shutil.which(dialect)
    if not executable:
        pytest.skip(f"Native {dialect} is unavailable")
    args = ["-NoProfile", "-Command"] if get_platform().is_windows and dialect in _PS_DIALECTS else ["-c"]
    return ShellInfo(dialect, executable, args)


@pytest.fixture
def isolated_home(monkeypatch, tmp_path):
    home = tmp_path / "home"
    (home / "Documents").mkdir(parents=True)
    work = tmp_path / "workspace"
    work.mkdir()
    for name in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("ZDOTDIR", str(work))
    monkeypatch.setenv("ICODE_TEST_LAUNCH_MARKER", "inherited-by-child")
    return work


@pytest.fixture
def launches(monkeypatch):
    launch = shell_module._shell_launch
    plans = []

    def record(shell, command, *, pipe=False):
        plan = launch(shell, command, pipe=pipe)
        plans.append(plan)
        return plan

    monkeypatch.setattr(shell_module, "_shell_launch", record)
    return plans


async def _exercise(
    shell, source, argv, cwd, *, mode, manually_approve=False, broad=False, may_launch=True, workdir=None
):
    path = get_platform().config_dir / "prejudge.yaml"
    await asyncio.to_thread(path.parent.mkdir, parents=True, exist_ok=True)
    policy = {
        "schema_version": 1,
        "mode": mode,
        "policy_id": "native-shell-test",
        "rules": [
            {
                "id": f"cmd-{idx}",
                "effect": "allow",
                "target": "command",
                "match": {"argv_first": [unit[0]]} if broad else {"argv_exact": list(unit)},
            }
            for idx, unit in enumerate(argv)
        ],
    }
    await asyncio.to_thread(path.write_text, yaml.safe_dump(policy), encoding="utf-8")
    decision = route(source, shell.name, load_policy(path))
    assert tuple(node.argv for node in analyze(source, dialect=shell.name).executable_nodes) == argv
    tools = ShellTools(replace(SessionEnvironment.capture(), cwd=str(cwd)), shell=shell)
    tool = tools.tools()[0]
    bus = EventBus()
    middleware = ApprovalMiddleware(
        ApprovalPolicy(ApprovalConfig(default="require"), tools=[tool]),
        bus,
        approval_mode=ApprovalMode.MANUAL,
        workspace_roots=[str(cwd)],
    )
    requests = []
    context = FunctionInvocationContext(tool, {"command": source, "workdir": workdir})

    async def respond(request: ApprovalRequest) -> None:
        requests.append(request.request_id)
        await bus.publish(ApprovalResponse(request_id=request.request_id, approved=manually_approve))

    async def execute() -> None:
        if not may_launch:
            pytest.fail("This case must stop before starting a shell")
        context.result = await tools.execute(
            command=source, reason="Verify a harmless shell launch", workdir=workdir, timeout=15
        )

    await bus.subscribe(ApprovalRequest, respond)
    try:
        await middleware.process(context, execute)
        [record] = middleware.drain_decisions()
        return decision.route, record["status"], str(context.result), requests
    finally:
        await bus.unsubscribe(ApprovalRequest, respond)
        await middleware.close()


async def test_zsh_bare_pipeline_uses_clean_shell_startup(isolated_home, launches, caplog):
    shell = _shell("zsh")
    await asyncio.to_thread(
        (isolated_home / ".zshenv").write_text,
        "alias fixture_alias='print fixture-alias'\n"
        "fixture_function() { print fixture-function; }\n"
        "print fixture-startup\n",
        encoding="utf-8",
    )
    source = "printf abc | cksum"
    static = (("printf", "abc"), ("cksum",))
    caplog.set_level(logging.INFO, logger=approval_module._prejudge_logger.name)

    route_, status, output, requests = await _exercise(
        shell, source, static, isolated_home, mode="shadow", manually_approve=True
    )
    assert route_ is Route.ALLOW and status == "user_approved" and len(requests) == 1
    assert "shadow route=allow" in caplog.text
    assert "fixture-startup" in output
    assert "1219131554 3" in output and "[exit_code: 0]" in output
    [(ordinary_argv, ordinary_env)] = launches
    assert ordinary_argv[-1][0] == shell.path and ordinary_argv[-1][-1] == source
    assert "-f" not in ordinary_argv[-1] and "noaliases" not in ordinary_argv[-1]

    route_, status, output, requests = await _exercise(shell, source, static, isolated_home, mode="enforce")
    assert route_ is Route.ALLOW and status == "prejudge_approved" and not requests
    assert "fixture-startup" not in output
    assert "1219131554 3" in output and "[exit_code: 0]" in output
    isolated_argv, isolated_env = launches[-1]
    assert isolated_argv[-1][:5] == (shell.path, "-f", "-d", "-o", "noaliases")
    assert isolated_argv[-1][-1] == source
    assert ordinary_env["PATH"] == isolated_env["PATH"]
    assert isolated_env["ICODE_TEST_LAUNCH_MARKER"] == "inherited-by-child"
    assert os.environ["ZDOTDIR"] == str(isolated_home)


@pytest.mark.parametrize("dialect", _PS_DIALECTS)
@pytest.mark.parametrize("native", [False, True], ids=["qualified-cmdlet", "native-signed-argument"])
async def test_powershell_launches_source_with_isolated_flags(dialect, native, isolated_home, launches, caplog):
    shell = _shell(dialect)
    if native and not shutil.which("findstr.exe"):
        pytest.skip("Windows findstr.exe is unavailable for the native argv control")
    # findstr accepts a standalone literal pattern. A lost plus sign would
    # also match the second line, so this verifies actual native argv.
    await asyncio.to_thread((isolated_home / "fixture.txt").write_text, "keep+5\nexclude5\n", encoding="utf-8")
    static = (
        (("findstr.exe", "/L", "+5", "fixture.txt"),) if native else ((_GET_CHILD_ITEM, "-LiteralPath", "fixture.txt"),)
    )
    source = " ".join(static[0])
    caplog.set_level(logging.INFO, logger=approval_module._prejudge_logger.name)

    route_, status, _, requests = await _exercise(shell, source, static, isolated_home, mode="shadow")
    assert route_ is Route.ALLOW and status == "user_rejected" and len(requests) == 1
    assert "shadow route=allow" in caplog.text
    assert not launches

    route_, status, output, requests = await _exercise(
        shell, source, static, isolated_home, mode="shadow", manually_approve=True
    )
    assert route_ is Route.ALLOW and status == "user_approved" and len(requests) == 1
    assert "[exit_code: 0]" in output
    [(ordinary_argv, ordinary_env)] = launches
    assert ordinary_argv[-1][0] == shell.path and ordinary_argv[-1][-1].endswith(source)
    assert ordinary_argv[-1][1:-1] == tuple(shell.args)

    route_, status, output, requests = await _exercise(shell, source, static, isolated_home, mode="enforce")
    assert route_ is Route.ALLOW and status == "prejudge_approved" and not requests
    assert "[exit_code: 0]" in output
    if native:
        assert "keep+5" in output and "exclude5" not in output
    else:
        assert "fixture.txt" in output
    argv, env = launches[-1]
    [exe, no_profile, non_interactive, encoded_flag, encoded_source] = argv[-1]
    assert (exe, no_profile, non_interactive, encoded_flag) == (
        shell.path,
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
    )
    expected_source = shell_module._prepare_pipe_command(source, shell) if sys.platform == "win32" else source
    assert base64.b64decode(encoded_source).decode("utf-16-le") == expected_source
    assert ordinary_env["PATH"] == env["PATH"]
    assert env["ICODE_TEST_LAUNCH_MARKER"] == "inherited-by-child"


@pytest.mark.parametrize("dialect", _PS_DIALECTS)
@pytest.mark.parametrize(
    ("static", "candidate", "reason"),
    [
        (("git", "--version"), Route.DEFER, "unresolved_executable"),
        (("icode-prejudge-fixture-unavailable.exe", "sample"), Route.ALLOW, "untrusted_launch_context"),
        (
            (_GET_CHILD_ITEM, "-LiteralPath", "Env:ICODE_TEST_LAUNCH_MARKER"),
            Route.DEFER,
            "sensitive_target",
        ),
    ],
    ids=["unqualified-name", "missing-native-program", "environment-provider"],
)
async def test_powershell_defers_in_both_modes(dialect, static, candidate, reason, isolated_home, launches, caplog):
    shell = _shell(dialect)
    source = " ".join(static)
    caplog.set_level(logging.INFO, logger=approval_module._prejudge_logger.name)
    for mode in ("shadow", "enforce"):
        route_, status, _, requests = await _exercise(shell, source, (static,), isolated_home, mode=mode)
        assert route_ is candidate and status == "user_rejected" and len(requests) == 1
        assert f"{mode} route=defer reason={reason}" in caplog.text
    assert not launches


@pytest.mark.parametrize("dialect", _PS_DIALECTS)
async def test_workspace_module_path_defers_before_launch(dialect, isolated_home, launches, caplog, monkeypatch):
    shell = _shell(dialect)
    monkeypatch.setenv("PSModulePath", str(isolated_home))
    static = ((_GET_CHILD_ITEM, "-LiteralPath", "."),)
    source = " ".join(static[0])
    caplog.set_level(logging.INFO, logger=approval_module._prejudge_logger.name)
    for mode in ("shadow", "enforce"):
        route_, status, _, requests = await _exercise(shell, source, static, isolated_home, mode=mode)
        assert route_ is Route.ALLOW and status == "user_rejected" and len(requests) == 1
        assert f"{mode} route=defer reason=untrusted_launch_context" in caplog.text
    assert not launches


@pytest.mark.parametrize("dialect", _PS_DIALECTS)
@pytest.mark.parametrize("scope", ["home", "documents"])
async def test_implicit_user_module_location_defers_before_launch(dialect, scope, isolated_home, caplog, monkeypatch):
    if sys.platform != "win32":
        pytest.skip("Windows Documents startup paths require the native host")
    shell = _shell(dialect)
    monkeypatch.delenv("PSModulePath", raising=False)
    home = Path(os.environ["USERPROFILE"])
    workspace = home if scope == "home" else home / "Documents"
    static = ((_GET_CHILD_ITEM, "-LiteralPath", "."),)
    caplog.set_level(logging.INFO, logger=approval_module._prejudge_logger.name)
    for mode in ("shadow", "enforce"):
        decision, status, _, requests = await _exercise(
            shell, " ".join(static[0]), static, workspace, mode=mode, may_launch=False
        )
        assert decision is Route.ALLOW and status == "user_rejected" and len(requests) == 1
        assert f"{mode} route=defer reason=untrusted_launch_context" in caplog.text


async def test_custom_powershell_module_configuration_defers_before_launch(isolated_home, caplog):
    shell = _shell("pwsh")
    locations = module_locations(shell, dict(os.environ))
    assert locations is not None
    _, configs = locations
    home = Path(os.environ["HOME"])
    (config,) = tuple(path for path in configs if path.is_relative_to(home))
    await asyncio.to_thread(config.parent.mkdir, parents=True, exist_ok=True)
    await asyncio.to_thread(config.write_text, json.dumps({"PSModulePath": str(isolated_home)}), encoding="utf-8")
    static = ((_GET_CHILD_ITEM, "-LiteralPath", "."),)
    caplog.set_level(logging.INFO, logger=approval_module._prejudge_logger.name)
    for mode in ("shadow", "enforce"):
        decision, status, _, requests = await _exercise(
            shell, " ".join(static[0]), static, isolated_home, mode=mode, may_launch=False
        )
        assert decision is Route.ALLOW and status == "user_rejected" and len(requests) == 1
        assert f"{mode} route=defer reason=untrusted_launch_context" in caplog.text


@pytest.mark.parametrize("dialect", _PS_DIALECTS)
@pytest.mark.parametrize(
    ("name", "literal", "decoded", "reason"),
    [
        (_GET_ITEM, r"'hKcU:\Software\Example'", r"hKcU:\Software\Example", "powershell_provider_path"),
        (_GET_CONTENT, '"Variable:fixture"', "Variable:fixture", "powershell_provider_path"),
        (_GET_ITEM, "Function:fixture", "Function:fixture", "powershell_provider_path"),
        (_GET_ITEM, r"CeRt:\CurrentUser", r"CeRt:\CurrentUser", "powershell_provider_path"),
        (
            _GET_ITEM,
            r"'Registry::HKEY_CURRENT_USER\Software'",
            r"Registry::HKEY_CURRENT_USER\Software",
            "powershell_provider_path",
        ),
        (_GET_ITEM, "WSMan:fixture", "WSMan:fixture", "powershell_provider_path"),
        (_GET_CONTENT, r"'\\fixture.invalid\share\file'", r"\\fixture.invalid\share\file", "windows_namespace_path"),
        (_GET_CONTENT, '"//fixture.invalid/share/file"', "//fixture.invalid/share/file", "windows_namespace_path"),
        (_GET_ITEM, r"'\\?\C:\fixture'", r"\\?\C:\fixture", "windows_namespace_path"),
        (_GET_ITEM, r"'\\.\fixture'", r"\\.\fixture", "windows_namespace_path"),
    ],
)
async def test_unsafe_powershell_arguments_stop_before_execution(
    dialect, name, literal, decoded, reason, isolated_home, caplog
):
    # A configured tool is needed at the middleware boundary. These
    # classification-only cases must never launch even if a regression occurs.
    tool_path = sys.executable
    shell = ShellInfo(dialect, tool_path, ["-Command"])
    caplog.set_level(logging.INFO, logger=approval_module._prejudge_logger.name)
    static = ((name, "-LiteralPath", decoded), (_GET_CHILD_ITEM, "."))
    source = f"{name} -LiteralPath {literal} | {_GET_CHILD_ITEM} ."
    for mode in ("shadow", "enforce"):
        result, status, _, requests = await _exercise(
            shell, source, static, isolated_home, mode=mode, broad=True, may_launch=False
        )
        assert result is Route.DEFER and status == "user_rejected" and len(requests) == 1
        assert f"{mode} route=defer reason={reason}" in caplog.text


@pytest.mark.parametrize(
    ("literal", "decoded"),
    [
        ("//fixture.invalid/share/file", "//fixture.invalid/share/file"),
        (r"'\\fixture.invalid\share\file'", r"\\fixture.invalid\share\file"),
        (r"'\\?\C:\fixture'", r"\\?\C:\fixture"),
        (r"'\\.\fixture'", r"\\.\fixture"),
        ("--path=//fixture.invalid/share/file", "--path=//fixture.invalid/share/file"),
    ],
)
async def test_git_bash_namespace_paths_stop_before_execution(literal, decoded, isolated_home, caplog):
    shell = ShellInfo("git_bash", sys.executable, ["-c"])
    source = f"cat {literal} | head"
    static = (("cat", decoded), ("head",))
    caplog.set_level(logging.INFO, logger=approval_module._prejudge_logger.name)
    # Enforce must also veto a legacy read-only shortcut. Shadow's prediction
    # can be checked independently without sending this source to any shell.
    decision, status, _, requests = await _exercise(
        shell, source, static, isolated_home, mode="enforce", broad=True, may_launch=False
    )
    assert decision is Route.DEFER and status == "user_rejected" and len(requests) == 1
    assert "enforce route=defer reason=windows_namespace_path" in caplog.text


@pytest.mark.parametrize("dialect", ("git_bash", *_PS_DIALECTS))
async def test_windows_namespace_workdir_defers_without_a_filesystem_probe(dialect, isolated_home, caplog, monkeypatch):
    if sys.platform != "win32":
        pytest.skip("Windows working directory path semantics require the native host")
    shell = ShellInfo(dialect, sys.executable, ["-c"] if dialect == "git_bash" else ["-Command"])
    executable = "review_fixture_tool" if dialect == "git_bash" else _GET_ITEM
    static = ((executable, "."),)
    cwd = r"\\fixture.invalid\share"
    caplog.set_level(logging.INFO, logger=approval_module._prejudge_logger.name)

    def forbid_probe(directory: str) -> str:
        pytest.fail("The approval target probe must never see a UNC working directory")

    monkeypatch.setattr(shell_module, "physical_dir", forbid_probe)
    tools = ShellTools(SessionEnvironment.capture(), shell=shell)
    assert tools.approval_targets({"workdir": cwd}).cwd is None
    for mode in ("shadow", "enforce"):
        decision, status, _, requests = await _exercise(
            shell, " ".join(static[0]), static, isolated_home, mode=mode, may_launch=False, workdir=cwd
        )
        assert decision is Route.ALLOW and status == "user_rejected" and len(requests) == 1
        assert f"{mode} route=defer reason=windows_namespace_workdir" in caplog.text


@pytest.mark.parametrize("dialect", _PS_DIALECTS)
@pytest.mark.parametrize("native", [False, True], ids=["cmdlet", "native-stderr"])
async def test_powershell_pipe_encoding_matches_ordinary_approval(
    dialect, native, isolated_home, launches, monkeypatch
):
    if sys.platform != "win32":
        pytest.skip("The PowerShell pipe comparison requires Windows")
    shell = _shell(dialect)
    text = "ASCII only\n中文\nMixed 汉字 café Ω\n"
    await asyncio.to_thread((isolated_home / "utf8.txt").write_text, text, encoding="utf-8")
    if native:
        await asyncio.to_thread(
            (isolated_home / "emit.py").write_text,
            "import sys\nfrom pathlib import Path\n"
            "sys.stdout.buffer.write(Path('utf8.txt').read_bytes())\n"
            "sys.stderr.buffer.write('stderr 中文 café Ω'.encode('utf-8'))\n",
            encoding="utf-8",
        )
        python = Path(sys.executable)
        monkeypatch.setenv("PATH", os.pathsep.join((str(python.parent), os.environ["PATH"])))
        static = ((python.name, "emit.py"),)
    else:
        static = ((_GET_CONTENT, "-Encoding", "UTF8", "-LiteralPath", "utf8.txt"),)
    source = " ".join(static[0])
    normal_route, normal_status, normal_output, normal_requests = await _exercise(
        shell, source, static, isolated_home, mode="shadow", manually_approve=True
    )
    decision, status, approved_output, requests = await _exercise(shell, source, static, isolated_home, mode="enforce")
    assert normal_route is decision is Route.ALLOW
    assert normal_status == "user_approved" and len(normal_requests) == 1
    assert status == "prejudge_approved" and not requests
    assert approved_output == normal_output
    assert all(line in approved_output for line in text.splitlines())
    if native:
        assert "stderr 中文 café Ω" in approved_output
    (ordinary, _), (isolated, _) = launches
    assert base64.b64decode(isolated[-1][-1]).decode("utf-16-le") == ordinary[-1][-1]
    assert ordinary[-1][-1] == shell_module._prepare_pipe_command(source, shell)


@pytest.mark.parametrize("dialect", _PS_DIALECTS)
async def test_powershell_launch_limit_defers_in_both_modes(dialect, isolated_home, caplog):
    if sys.platform != "win32":
        pytest.skip("The command line limit applies to the Windows pipe backend")
    shell = _shell(dialect)
    prefix = f"{_GET_CONTENT} -LiteralPath "
    caplog.set_level(logging.INFO, logger=approval_module._prejudge_logger.name)
    for length in range(11_000, 13_000):
        if exceeds_isolated_launch_limit(shell, prefix + "x" * length):
            break
    else:
        pytest.fail("Expected the encoded Windows command line to exceed 32,767 UTF-16 units")
    short = prefix + "x" * (length - 1)
    assert not exceeds_isolated_launch_limit(shell, prefix + "sample")
    assert not exceeds_isolated_launch_limit(shell, short)
    flags, payload = powershell_isolated_invocation(short, pipe=True)
    units = len(subprocess.list2cmdline((shell.path, *flags, payload)).encode("utf-16-le")) // 2 + 1
    assert 32_763 <= units <= 32_767
    argument = "x" * length
    static = ((_GET_CONTENT, "-LiteralPath", argument),)
    for mode in ("shadow", "enforce"):
        decision, status, _, requests = await _exercise(
            shell, prefix + argument, static, isolated_home, mode=mode, broad=True, may_launch=False
        )
        assert decision is Route.ALLOW and status == "user_rejected" and len(requests) == 1
        assert f"{mode} route=defer reason=launch_command_too_long" in caplog.text


@pytest.mark.parametrize("dialect", _PS_DIALECTS)
def test_native_powershell_qualifies_the_system_cmdlet(dialect, isolated_home, monkeypatch):
    shell = _shell(dialect)
    monkeypatch.delenv("PSModulePath", raising=False)
    source = (
        f"$info = Get-Command -Name {_GET_CHILD_ITEM} -ErrorAction Stop; "
        "@{ Type = [string] $info.CommandType; Module = $info.ModuleName; "
        "SystemModule = $info.Module.ModuleBase.StartsWith($PSHOME, [StringComparison]::OrdinalIgnoreCase); "
        "ModulePath = $env:PSModulePath } "
        "| ConvertTo-Json -Compress"
    )
    encoded = base64.b64encode(source.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        [shell.path, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        cwd=isolated_home,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
        **windows_hidden_subprocess_kwargs(),
    )
    resolution = json.loads(result.stdout)
    effective = resolution.pop("ModulePath")
    assert resolution == {
        "Type": "Cmdlet",
        "Module": "Microsoft.PowerShell.Management",
        "SystemModule": True,
    }
    if sys.platform == "win32":
        locations = module_locations(shell, dict(os.environ))
        assert locations is not None
        predicted, _ = locations
        edition = "WindowsPowerShell" if dialect == "powershell" else "PowerShell"
        expected = Path(os.environ["USERPROFILE"]) / "Documents" / edition / "Modules"
        actual = {Path(item) for item in effective.split(os.pathsep) if item}
        assert expected in actual
        assert actual <= {Path(item) for item in predicted}
