# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Structured pre-judge middleware decisions without importing optional parsers."""

from __future__ import annotations

import pytest

from chrys.foundation.events.bus import EventBus
from chrys.foundation.events.types import ApprovalRequest, ApprovalResponse, InvocationToolCallResult
from chrys.foundation.models.invocations import InvocationOrigin
from chrys.foundation.tool_kinds import KIND_SHELL, set_tool_kind
from chrys.foundation.tool_result_metadata import TOOL_ERROR_KIND_METADATA_KEY
from chrys.kernel.middleware import FunctionInvocationContext
from chrys.kernel.tools import FunctionTool
from chrys.service.agent_middleware.control import approval as approval_module
from chrys.service.agent_middleware.control.approval import ApprovalMiddleware
from chrys.service.agent_middleware.events.tool_events import ToolEventMiddleware
from chrys.service.approval.policy import ApprovalMode, ApprovalPolicy
from chrys.service.approval.prejudge_v2 import Policy, PreJudgeResult, Route
from chrys.service.profiles.agents.schema import ApprovalConfig
from tests.support.event_capture import capture_events


@pytest.mark.parametrize(
    ("mode", "suggestion", "expected_executions", "expected_requests"),
    [
        ("enforce", Route.BLOCK, 0, 0),
        ("enforce", Route.ALLOW, 1, 0),
        ("enforce", Route.DEFER, 1, 1),
        ("shadow", Route.BLOCK, 1, 0),
    ],
)
async def test_shell_routes_do_not_bypass_or_mutate_legacy(
    monkeypatch, mode, suggestion, expected_executions, expected_requests
):
    monkeypatch.setattr(approval_module, "load_policy", lambda _: Policy(mode, "pilot", ()))
    monkeypatch.setattr(
        approval_module,
        "route",
        lambda cmd, dialect, policy: PreJudgeResult(suggestion, "test", (), (), policy.policy_id, "digest"),
    )
    tool = FunctionTool(name="bash")
    set_tool_kind(tool, KIND_SHELL)
    bus = EventBus()
    requests = []

    async def approve(req: ApprovalRequest):
        requests.append(req)
        await bus.publish(ApprovalResponse(request_id=req.request_id, approved=True))

    await bus.subscribe(ApprovalRequest, approve)
    middleware = ApprovalMiddleware(
        ApprovalPolicy(ApprovalConfig(default="require"), tools=[tool]),
        bus,
        approval_mode=ApprovalMode.MANUAL,
    )
    context = FunctionInvocationContext(tool, {"command": "ls"})
    executed = 0

    async def execute():
        nonlocal executed
        executed += 1

    try:
        await middleware.process(context, execute)
        assert executed == expected_executions
        assert len(requests) == expected_requests
        if suggestion is Route.BLOCK and mode == "enforce":
            assert context.result.startswith("Error:")
    finally:
        await middleware.close()
        await bus.unsubscribe(ApprovalRequest, approve)


async def test_non_shell_tool_never_invokes_prejudge(monkeypatch):
    monkeypatch.setattr(approval_module, "load_policy", lambda _: Policy("enforce", "pilot", ()))

    def forbidden(*args, **kwargs):
        pytest.fail("Non-shell call must not enter pre-judge")

    monkeypatch.setattr(approval_module, "route", forbidden)
    tool = FunctionTool(name="other_tool")
    context = FunctionInvocationContext(tool, {})
    bus = EventBus()
    middleware = ApprovalMiddleware(
        ApprovalPolicy(ApprovalConfig(default="skip"), tools=[tool]),
        bus,
    )
    executed = False

    async def execute():
        nonlocal executed
        executed = True

    try:
        await middleware.process(context, execute)
        assert executed
    finally:
        await middleware.close()


@pytest.mark.parametrize(
    ("source", "expected_kind"),
    [
        ("prejudge", "prejudge_blocked"),
        ("approval_invalidated", "approval_invalidated"),
    ],
)
async def test_middleware_rejection_source_is_persisted(monkeypatch, source, expected_kind):
    """Exercise real ApprovalMiddleware before ToolEventMiddleware persistence."""
    monkeypatch.setattr(approval_module, "load_policy", lambda _: Policy("enforce", "pilot", ()))
    bus = EventBus()
    results = await capture_events(bus, InvocationToolCallResult)
    tool = FunctionTool(name="bash")
    set_tool_kind(tool, KIND_SHELL)
    approval = ApprovalMiddleware(
        ApprovalPolicy(ApprovalConfig(default="require"), tools=[tool]),
        bus,
        approval_mode=ApprovalMode.MANUAL,
    )
    event_mw = ToolEventMiddleware(
        bus,
        session_id="test",
        origin=InvocationOrigin("turn", "test", "turn-prejudge", None),
    )
    context = FunctionInvocationContext(tool, {"command": "rm fixture"})
    executed = False

    async def execute():
        nonlocal executed
        executed = True

    if source == "prejudge":
        monkeypatch.setattr(
            approval_module,
            "route",
            lambda cmd, dialect, policy: PreJudgeResult(
                Route.BLOCK, "matched_block", (), (), policy.policy_id, "digest"
            ),
        )
    else:
        monkeypatch.setattr(
            approval_module,
            "route",
            lambda cmd, dialect, policy: PreJudgeResult(
                Route.DEFER, "unmatched_unit", (), (), policy.policy_id, "digest"
            ),
        )

        async def reply(request: ApprovalRequest) -> None:
            await bus.publish(
                ApprovalResponse(
                    request_id=request.request_id,
                    approved=True,
                    modified_args={"command": "echo approved"},
                )
            )

        await bus.subscribe(ApprovalRequest, reply)

        async def rewrite_edited_command(**kwargs) -> bool:
            kwargs["context"].arguments["command"] = "echo rewritten"
            return False

        monkeypatch.setattr(approval_module, "apply_before_tool_hooks", rewrite_edited_command)

    try:
        await event_mw.process(context, lambda: approval.process(context, execute))
        assert not executed
        assert len(results) == 1
        assert results[0].metadata[TOOL_ERROR_KIND_METADATA_KEY] == expected_kind
        assert "approval" not in results[0].metadata
    finally:
        await approval.close()
