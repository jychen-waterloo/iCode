# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Formal input validation leaves ACP permission requests open for human approval."""

from __future__ import annotations

import asyncio
from unittest.mock import create_autospec

import pytest
from acp.schema import PermissionOption, ToolCallUpdate

from chrys.foundation.events.bus import EventBus
from chrys.foundation.events.types import ApprovalRequest, ApprovalResponse, ApprovalReviewed
from chrys.foundation.models.invocations import InvocationOrigin
from chrys.orchestration.invoker.acp_protocol import AcpPermissionBroker, AcpUpdateTranslator
from chrys.service.approval.judge import ApprovalJudge
from chrys.service.approval.policy import ApprovalMode
from chrys.service.approval.turn_context import TurnContextHolder
from chrys.service.profiles.models.schema import ModelProfile
from tests.support.event_capture import capture_event_sequence
from tests.support.waiting import wait_for


@pytest.mark.parametrize(
    "kind,messages",
    [(None, ["Inspect source"]), ("other", ["Inspect source"]), ("read", [])],
    ids=["missing-kind", "unmapped-kind", "missing-user-context"],
)
async def test_invalid_formal_context_waits_for_human_allow(monkeypatch, kind, messages):
    bus = EventBus()
    context = TurnContextHolder()
    context.replace(messages)
    judge = ApprovalJudge(
        ModelProfile(
            id="acp-formal-test",
            name="ACP Formal test",
            model_id="test",
            base_url="https://provider.test/v1",
            api_key="synthetic-key",
            formal_enabled=True,
        )
    )
    get_client = create_autospec(judge._get_client, side_effect=AssertionError("Model must not be called"))
    monkeypatch.setattr(judge, "_get_client", get_client)
    broker = AcpPermissionBroker(
        event_bus=bus,
        session_id="parent",
        caller_name="External",
        mode_getter=lambda: ApprovalMode.AUTO,
        turn_context=context,
        workspace_roots=["/workspace"],
        workspace_cwd="/workspace",
        approval_judge=judge,
        ask_user_timeout_seconds=None,
    )
    translator = AcpUpdateTranslator(
        event_bus=bus,
        session_id="parent",
        agent_name="External",
        invocation_id="inv",
        attempt=1,
        origin=InvocationOrigin("sub_agent", "parent", "inv", None),
    )
    broker.set_translator(translator)
    async with capture_event_sequence(bus, ApprovalRequest, ApprovalReviewed) as events:
        task = asyncio.create_task(
            broker.on_permission_request(
                ToolCallUpdate(toolCallId="call", title="Inspect source", kind=kind, rawInput={"path": "main.py"}),
                [PermissionOption(optionId="allow", name="Allow", kind="allow_once")],
            )
        )
        try:
            await wait_for(
                lambda: any(isinstance(event, ApprovalReviewed) for event in events) or task.done(),
                description="Formal review of the pending ACP permission",
            )
            if task.done():
                await task
            assert not task.done(), "Invalid input must leave the permission pending for human review"
            request, review = events
            assert isinstance(request, ApprovalRequest)
            assert isinstance(review, ApprovalReviewed)
            assert request.judging is True
            assert review.request_id == request.request_id
            assert review.approved is False
            assert review.reason == "Approval judge input is invalid"
            get_client.assert_not_called()
            await bus.publish(ApprovalResponse(request_id=request.request_id, approved=True, session_id="parent"))
            decision = await asyncio.wait_for(task, timeout=5)
            assert decision.action == "allow"
            assert decision.option_id == "allow"
            reviews = [
                item["update"]
                for item in translator.translated_updates
                if item["update"]["sessionUpdate"] == "permission_review"
            ]
            assert len(reviews) == 1
            assert reviews[0]["request_id"] == request.request_id
            assert reviews[0]["formal_audit"]["failure_reason"] == "invalid_input"
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await broker.close()
            await judge.aclose()
