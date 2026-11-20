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
from dataclasses import replace

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
from chrys.service.profiles.agents.schema import ApprovalConfig
from chrys.service.tools.builtins import shell as shell_module
from chrys.service.tools.builtins.shell import ShellTools
from tests.support.prejudge import require_grammars

require_grammars("tree_sitter", "tree_sitter_bash", "tree_sitter_zsh", "tree_sitter_pwsh")

_PS_DIALECTS = ("powershell", "pwsh")
_GET_CHILD_ITEM = r"Microsoft.PowerShell.Management\Get-ChildItem"


def _shell(dialect):
    executable = shutil.which(dialect)
    if not executable:
        pytest.skip(f"Native {dialect} is unavailable")
    args = ["-NoProfile", "-Command"] if get_platform().is_windows and dialect in _PS_DIALECTS else ["-c"]
    return ShellInfo(dialect, executable, args)


@pytest.fixture
def isolated_home(monkeypatch, tmp_path):
    for name in ("HOME", "USERPROFILE", "APPDATA", "ZDOTDIR"):
        monkeypatch.setenv(name, str(tmp_path))
    monkeypatch.setenv("ICODE_TEST_LAUNCH_MARKER", "inherited-by-child")
    return tmp_path


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


async def _exercise(shell, source, argv, cwd, *, mode, manually_approve=False):
    path = get_platform().config_dir / "prejudge.yaml"
    await asyncio.to_thread(path.parent.mkdir, parents=True, exist_ok=True)
    policy = {
        "schema_version": 1,
        "mode": mode,
        "policy_id": "native-shell-test",
        "rules": [
            {"id": f"cmd-{idx}", "effect": "allow", "target": "command", "match": {"argv_exact": list(unit)}}
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
    context = FunctionInvocationContext(tool, {"command": source})

    async def respond(request: ApprovalRequest) -> None:
        requests.append(request.request_id)
        await bus.publish(ApprovalResponse(request_id=request.request_id, approved=manually_approve))

    async def execute() -> None:
        context.result = await tools.execute(command=source, reason="Verify a harmless shell launch", timeout=15)

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
    assert base64.b64decode(encoded_source).decode("utf-16-le") == source
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
def test_native_powershell_qualifies_the_system_cmdlet(dialect, isolated_home):
    shell = _shell(dialect)
    source = (
        f"$info = Get-Command -Name {_GET_CHILD_ITEM} -ErrorAction Stop; "
        "@{ Type = [string] $info.CommandType; Module = $info.ModuleName; "
        "SystemModule = $info.Module.ModuleBase.StartsWith($PSHOME, [StringComparison]::OrdinalIgnoreCase) } "
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
    assert json.loads(result.stdout) == {
        "Type": "Cmdlet",
        "Module": "Microsoft.PowerShell.Management",
        "SystemModule": True,
    }
