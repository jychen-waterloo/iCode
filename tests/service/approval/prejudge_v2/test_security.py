# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Defensive parser regressions and real approval-to-execution boundaries."""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess

import pytest

from chrys.foundation.events.bus import EventBus
from chrys.foundation.events.types import ApprovalRequest, ApprovalResponse
from chrys.foundation.models.session_env import SessionEnvironment
from chrys.foundation.platform import ShellInfo, get_platform
from chrys.foundation.platform.process import windows_hidden_subprocess_kwargs
from chrys.kernel.middleware import FunctionInvocationContext
from chrys.service.agent_middleware._metadata_keys import _APPROVAL_REJECTED_KEY, _REJECTION_SOURCE_KEY
from chrys.service.agent_middleware.control.approval import ApprovalMiddleware
from chrys.service.approval.policy import ApprovalMode, ApprovalPolicy
from chrys.service.approval.prejudge_v2 import Matcher, Policy, Route, Rule, analyze, route
from chrys.service.approval.prejudge_v2.execution import isolated_shell_call, prepare_execution
from chrys.service.approval.safety_classifier import shell_command_may_access_sensitive_data
from chrys.service.mutations.trace import shell_trace_argv
from chrys.service.profiles.agents.schema import ApprovalConfig
from chrys.service.tools.builtins.shell import ShellTools, _shell_argv_variants
from tests.support.prejudge import require_grammars

require_grammars("tree_sitter", "tree_sitter_bash", "tree_sitter_zsh", "tree_sitter_pwsh")

_DIALECTS = ("bash", "git_bash", "zsh", "powershell", "pwsh")


@pytest.mark.parametrize("dialect", _DIALECTS)
@pytest.mark.parametrize("character", ["\r", "\v", "\f", "\0", "\x1b", "\u0085", "\u2028"])
def test_uncertified_byte_sequences_have_no_argv(dialect, character):
    result = analyze(f"printf left{character}right", dialect=dialect)
    assert not result.coverage_complete
    assert not result.executable_nodes


@pytest.mark.parametrize("dialect", _DIALECTS)
def test_controls_and_comments_defer_while_horizontal_layout_is_certified(dialect):
    rule = Rule("sample", Route.ALLOW, Matcher("argv_exact", ("printf", "text")))
    policy = Policy("enforce", "certify", (rule,))
    if dialect in {"powershell", "pwsh"}:
        assert route("printf\ttext", dialect, policy).route is Route.DEFER
        lines = analyze("printf text\r\nother value", dialect=dialect)
        assert lines.coverage_complete
        assert [node.argv for node in lines.executable_nodes] == [("printf", "text"), ("other", "value")]
    else:
        assert analyze("printf\ttext", dialect=dialect).executable_nodes[0].argv == ("printf", "text")
    continuation = chr(96) if dialect in {"powershell", "pwsh"} else "\\"
    for source in (
        "printf text # note",
        "printf text > fixture",
        "printf text |",
        f"printf {continuation}\ntext",
        f"printf {continuation}\r\ntext",
        f"printf {continuation}\ttext",
        "printf text\nother",
    ):
        assert route(source, dialect, policy).route is Route.DEFER


@pytest.mark.parametrize("dialect", ["bash", "git_bash"])
def test_bash_does_not_certify_unmodeled_tokens(dialect):
    for command in ("printf text $", 'printf $"text"'):
        assert not analyze(command, dialect=dialect).coverage_complete
    assert analyze("printf 'te'xt", dialect=dialect).executable_nodes[0].argv == ("printf", "text")


@pytest.mark.parametrize(
    ("dialect", "executable", "argument", "sensitive"),
    [
        ("bash", "/usr/bin/printf", ".e'n'v", True),
        ("git_bash", "/usr/bin/printf", "$'\\x2eenv'", True),
        ("zsh", "/usr/bin/printf", "'.env'", True),
        ("powershell", "C:/Windows/System32/whoami.exe", "'.env:fixture'", True),
        ("pwsh", "C:/Windows/System32/whoami.exe", "'.env:fixture'", True),
        *((dialect, "fixture_command", "sample # note", False) for dialect in _DIALECTS),
    ],
)
async def test_ambiguous_source_and_sensitive_argv_require_approval(dialect, executable, argument, sensitive, tmp_path):
    source = f"{executable} {argument}"
    if dialect in {"bash", "git_bash"}:
        assert not shell_command_may_access_sensitive_data(source, shell_name=dialect)
    path = get_platform().config_dir / "prejudge.yaml"
    await asyncio.to_thread(path.parent.mkdir, parents=True, exist_ok=True)
    await asyncio.to_thread(
        path.write_text,
        "schema_version: 1\nmode: enforce\npolicy_id: sampled\nrules:\n"
        f"  - id: sample\n    effect: allow\n    target: command\n    match: {{argv_first: ['{executable}']}}\n",
        encoding="utf-8",
    )
    policy = Policy("enforce", "sampled", (Rule("sample", Route.ALLOW, Matcher("argv_first", (executable,))),))
    decision = route(source, dialect, policy)
    assert decision.route is Route.DEFER and decision.sensitive is sensitive
    if sensitive:
        assert decision.reason_code == "sensitive_target"
    bus = EventBus()
    tools = ShellTools(SessionEnvironment.capture(), shell=ShellInfo(dialect, str(tmp_path / "unused"), ["-c"]))
    tool = tools.tools()[0]
    middleware = ApprovalMiddleware(
        ApprovalPolicy(ApprovalConfig(default="require"), tools=[tool]), bus, approval_mode=ApprovalMode.MANUAL
    )
    requests = []

    async def reject(request: ApprovalRequest) -> None:
        requests.append(request)
        await bus.publish(ApprovalResponse(request_id=request.request_id, approved=False))

    async def launch() -> None:
        pytest.fail("An uncertified source or sensitive decoded target reached the execution callback")

    await bus.subscribe(ApprovalRequest, reject)
    try:
        context = FunctionInvocationContext(tool, {"command": source})
        await middleware.process(context, launch)
        assert len(requests) == 1
        assert "rejected by user" in str(context.result)
        assert context.metadata[_APPROVAL_REJECTED_KEY]
        assert context.metadata[_REJECTION_SOURCE_KEY] == "user"
        assert middleware.drain_decisions()[-1]["status"] == "user_rejected"
    finally:
        await bus.unsubscribe(ApprovalRequest, reject)
        await middleware.close()


@pytest.mark.parametrize("dialect", ["bash", "git_bash"])
def test_native_bash_agrees_on_certified_literals(dialect, tmp_path):
    windows = get_platform().is_windows
    if windows != (dialect == "git_bash"):
        pytest.skip("This Bash runtime is exercised on its native platform")
    choices = get_platform().extra_shells
    executable = (
        next((shell.path for shell in choices if shell.name == "git_bash"), None) if windows else shutil.which("bash")
    )
    if not executable:
        if os.environ.get("CI"):
            pytest.fail(f"CI requires {dialect} for native validation")
        pytest.skip(f"{dialect} is not installed")
    source = "printf\t'[%s]' 'two words' ''"
    assert analyze(source, dialect=dialect).executable_nodes[0].argv == ("printf", "[%s]", "two words", "")
    env = {key: value for key, value in os.environ.items() if key not in {"BASH_ENV", "ENV"}}
    result = subprocess.run(
        [executable, "--noprofile", "--norc", "-c", source],
        env={**env, "HOME": str(tmp_path), "USERPROFILE": str(tmp_path), "APPDATA": str(tmp_path)},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
        **windows_hidden_subprocess_kwargs(),
    )
    assert result.stdout == "[two words][]"


@pytest.mark.parametrize("dialect", ["bash", "zsh", "pwsh"])
async def test_approval_launches_certified_argv_without_a_shell(dialect, tmp_path):
    if get_platform().is_windows:
        pytest.skip("Trusted direct execution is POSIX-only")
    source = "/usr/bin/git '--version'"
    argv = ("/usr/bin/git", "--version")
    shell = ShellInfo(dialect, str(tmp_path / "unavailable-shell"), ["-c"])
    tools = ShellTools(SessionEnvironment.capture(), shell=shell)
    tool = tools.tools()[0]
    path = get_platform().config_dir / "prejudge.yaml"
    await asyncio.to_thread(path.parent.mkdir, parents=True, exist_ok=True)
    await asyncio.to_thread(
        path.write_text,
        "schema_version: 1\nmode: enforce\npolicy_id: native\nrules:\n"
        "  - id: print\n    effect: allow\n    target: command\n"
        "    match: {argv_exact: ['/usr/bin/git', '--version']}\n",
        encoding="utf-8",
    )
    assert prepare_execution(dialect, source, argv) is not None
    bus = EventBus()
    middleware = ApprovalMiddleware(
        ApprovalPolicy(ApprovalConfig(default="require"), tools=[tool]), bus, approval_mode=ApprovalMode.MANUAL
    )
    context = FunctionInvocationContext(tool, {"command": source})
    output = []

    async def reject(request: ApprovalRequest) -> None:
        await bus.publish(ApprovalResponse(request_id=request.request_id, approved=False))

    async def launch() -> None:
        output.append(await tools.execute(command=source, reason="Verify static argv", timeout=10))

    await bus.subscribe(ApprovalRequest, reject)
    try:
        await middleware.process(context, launch)
        assert output and "git version" in output[0] and "[exit_code: 0]" in output[0]
        assert middleware.drain_decisions()[-1]["status"] == "prejudge_approved"
        assert isolated_shell_call.get() is None
    finally:
        await bus.unsubscribe(ApprovalRequest, reject)
        await middleware.close()


async def test_certified_argv_is_call_bound_and_retries_keep_the_same_argv(monkeypatch):
    from chrys.service.approval.prejudge_v2 import execution

    monkeypatch.setattr(execution, "_trusted_system_executable", lambda path: path == "/usr/bin/git")
    source = "/usr/bin/git --version"
    argv = ("/usr/bin/git", "--version")
    shell = ShellInfo("zsh", "/bin/zsh", ["-c"])
    approval = prepare_execution("zsh", source, argv)
    assert approval is not None
    token = isolated_shell_call.set(approval)
    tracer = shell_trace_argv.set(("trace-fixture",))
    try:

        async def claim_from_child():
            return approval.claim("zsh", source)

        assert not await asyncio.create_task(claim_from_child())
        assert not approval.claim("bash", source)
        assert not approval.claim("zsh", "/usr/bin/git")
        assert approval.claim("zsh", source)
        assert _shell_argv_variants(shell, source) == [("trace-fixture", *argv), argv]
        with pytest.raises(PermissionError, match="no longer binds"):
            _shell_argv_variants(shell, source)
    finally:
        approval.active = False
        shell_trace_argv.reset(tracer)
        isolated_shell_call.reset(token)
    assert isolated_shell_call.get() is None


@pytest.mark.parametrize("name", ["bash", "git_bash", "zsh", "powershell", "pwsh"])
async def test_workspace_path_is_not_an_executable_identity(name, tmp_path):
    fixture = tmp_path / "fixture.exe"
    await asyncio.to_thread(fixture.touch)
    assert prepare_execution(name, str(fixture), (str(fixture),)) is None
