# Copyright (c) 2026 Chrys. All rights reserved.

"""Minimal Formal/Jev runtime contracts using the real factory and mocked HTTP."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import create_autospec

import httpx
import pytest

from chrys.service.approval.judge import ApprovalJudge, JudgeVerdict
from chrys.service.approval.predicate import PredicateAssetError, load_default_asset, validate_predicate_response
from chrys.service.llm import clients
from chrys.service.profiles.models.schema import ModelProfile


def _values() -> dict[str, bool]:
    return {
        "reasonable_step_for_task": True,
        "malformed_critical_parameters": False,
        "sensitive_or_account": False,
        "tool_laundering": False,
        "deletion": False,
    }


def _reply(values: dict[str, bool], model: str) -> str | dict[str, Any]:
    if model == "test":
        return json.dumps(values)
    return {
        "answers": {key: {"type": "choice", "choice": str(value).lower()} for key, value in values.items()},
        "usage": {"input_tokens": 2, "output_tokens": 3},
    }


@asynccontextmanager
async def _judge(
    monkeypatch: pytest.MonkeyPatch,
    replies: list[str | dict[str, Any]],
    *,
    model: str = "test",
    formal: bool = True,
) -> AsyncIterator[tuple[ApprovalJudge, list[httpx.Request]]]:
    calls: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        reply = replies.pop(0)
        if request.url.path.endswith("/chat/completions"):
            reply = {
                "id": "test",
                "object": "chat.completion",
                "created": 1,
                "model": model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
            }
        return httpx.Response(200, json=reply)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        monkeypatch.setattr(
            clients,
            "_build_profile_http_client",
            create_autospec(clients._build_profile_http_client, return_value=http),
        )
        judge = ApprovalJudge(
            ModelProfile(
                id="core-test",
                name="Core test",
                model_id=model,
                base_url="https://provider.test/v1",
                api_key="synthetic-key",
                formal_enabled=formal,
                stream=formal and model != "test",
                http_max_retries=0,
                http_read_timeout=5,
            )
        )
        try:
            yield judge, calls
        finally:
            await judge.aclose()


async def _evaluate(judge: ApprovalJudge) -> JudgeVerdict:
    return await judge.evaluate("Inspect source", "read_file", "filesystem.read", {"path": "main.py"}, ["/workspace"])


@pytest.mark.parametrize("model", ["test", "typesafe/jev-test", "~typesafe/jev-test"])
@pytest.mark.parametrize("flipped", [None, *_values()])
async def test_fixed_decision_and_provider_routing(monkeypatch, model, flipped):
    values = _values()
    if flipped is not None:
        values[flipped] = not values[flipped]
    async with _judge(monkeypatch, [_reply(values, model)], model=model) as (judge, calls):
        verdict = await _evaluate(judge)
        assert verdict.approved is (flipped is None)
        assert verdict.audit["route"] == "predicate_only_v1"
        assert verdict.audit["application_attempts"] == verdict.audit["transport_attempts"] == len(calls) == 1
        assert verdict.audit["usage"]["total_token_count"] == 5
        assert verdict.audit["predicate_results"] == [{"id": key, "value": value} for key, value in values.items()]
        body = json.loads(calls[0].content)
        assert body["model"] == model
        if model == "test":
            assert calls[0].url.path == "/v1/chat/completions"
            messages = body["messages"]
        else:
            assert calls[0].url.path == "/v1/decisions"
            assert body["questions"] == {
                p.id: {
                    "type": "choice",
                    "instructions": {"question": p.question},
                    "criteria": {"true": "The condition holds.", "false": "The condition does not hold."},
                }
                for p in load_default_asset().principles
            }
            assert "stream" not in body
            messages = body["state"]["messages"]
        assert [message["role"] for message in messages] == ["system", "user"]
        assert "main.py" in messages[1]["content"]
        assert calls[0].headers["authorization"] == "Bearer synthetic-key"
        assert "synthetic-key" not in calls[0].content.decode()


@pytest.mark.parametrize("model", ["test", "typesafe/jev-test"])
@pytest.mark.parametrize("recovers", [False, True])
async def test_invalid_response_retries_or_requires_review_without_direct(monkeypatch, model, recovers):
    invalid = "{}" if model == "test" else {"answers": {}}
    replies = [invalid, _reply(_values(), model)] if recovers else [invalid] * 3
    async with _judge(monkeypatch, replies, model=model) as (judge, calls):
        verdict = await _evaluate(judge)
        assert verdict.approved is recovers
        assert len(calls) == verdict.audit["application_attempts"] == (2 if recovers else 3)
        assert verdict.audit["stages"] == ["predicate"]
        assert verdict.audit["failure_reason"] == (None if recovers else "invalid_shape")
        body = json.loads(calls[1].content)
        messages = body["messages"] if model == "test" else body["state"]["messages"]
        assert [message["role"] for message in messages] == ["system", "user", "assistant", "user"]
        assert "Invalid response" in messages[-1]["content"]


async def test_disabled_formal_keeps_direct_even_with_jev_model_name(monkeypatch):
    async with _judge(
        monkeypatch, ['{"approved":true,"reason":"direct"}'], model="typesafe/jev-test", formal=False
    ) as (judge, calls):
        verdict = await _evaluate(judge)
        assert verdict.approved is True
        assert verdict.reason == "direct"
        assert verdict.audit is None
        assert len(calls) == 1
        assert calls[0].url.path == "/v1/chat/completions"


@pytest.mark.parametrize("message,kind", [("Inspect source", ""), ("", "filesystem.read")])
async def test_missing_context_retains_manual_review_policy(monkeypatch, message, kind):
    async with _judge(monkeypatch, []) as (judge, calls):
        verdict = await judge.evaluate(message, "read_file", kind, {"path": "main.py"}, ["/workspace"])
        assert verdict.approved is False
        assert verdict.reason == "Approval judge input is invalid"
        assert calls == []


@pytest.mark.parametrize("model", ["test", "typesafe/jev-test"])
async def test_empty_latest_message_uses_shared_user_context(monkeypatch, model):
    async with _judge(monkeypatch, [_reply(_values(), model)], model=model) as (judge, calls):
        verdict = await judge.evaluate(
            "",
            "read_file",
            "filesystem.read",
            {"path": "main.py"},
            ["/workspace"],
            user_messages=["Inspect the parent session source"],
        )
        assert verdict.approved is True
        assert verdict.audit["application_attempts"] == len(calls) == 1
        body = json.loads(calls[0].content)
        messages = body["messages"] if model == "test" else body["state"]["messages"]
        assert "Inspect the parent session source" in messages[1]["content"]


@pytest.mark.parametrize(
    "response",
    [
        "{}",
        json.dumps(_values() | {"deletion": "false"}),
        json.dumps(_values() | {"extra": False}),
        json.dumps(_values()).replace('"deletion": false', '"deletion": true, "deletion": false'),
    ],
)
def test_predicates_require_complete_boolean_values(response):
    with pytest.raises(PredicateAssetError):
        validate_predicate_response(response, load_default_asset())


@pytest.mark.parametrize(
    "response",
    [
        pytest.param(f"```json\n{json.dumps(_values())}\n```", id="json"),
        pytest.param(f"```\n{json.dumps(_values())}\n```", id="plain"),
        pytest.param(f" \n```JSON\n{json.dumps(_values())}\n```\n ", id="uppercase-with-whitespace"),
    ],
)
def test_predicates_accept_complete_fence(response):
    values = validate_predicate_response(response, load_default_asset())
    assert {value.id: value.value for value in values} == _values()


@pytest.mark.parametrize(
    "response",
    [
        pytest.param(f"Here you go:\n```json\n{json.dumps(_values())}\n```", id="leading-prose"),
        pytest.param(f"```json\n{json.dumps(_values())}\n```\n```json\n{{}}\n```", id="two-blocks"),
        pytest.param(
            "```json\n" + json.dumps(_values()).replace(", ", ",\n```\n```json\n", 1) + "\n```",
            id="object-split-across-blocks",
        ),
        pytest.param(f"```json\n{json.dumps(_values())}", id="unterminated"),
        pytest.param(
            "```json\n"
            + json.dumps(_values()).replace('"deletion": false', '"deletion": true, "deletion": false')
            + "\n```",
            id="duplicate-key",
        ),
    ],
)
def test_predicates_reject_invalid_fenced_response(response):
    with pytest.raises(PredicateAssetError):
        validate_predicate_response(response, load_default_asset())


@pytest.mark.parametrize("needs_review", [False, True], ids=["approve", "human-review"])
async def test_fenced_formal_response_needs_only_one_model_call(monkeypatch, needs_review):
    values = _values() | {"deletion": needs_review}
    async with _judge(monkeypatch, [f"```json\n{json.dumps(values)}\n```"]) as (judge, calls):
        verdict = await _evaluate(judge)
        assert verdict.approved is not needs_review
        assert verdict.audit["application_attempts"] == verdict.audit["transport_attempts"] == len(calls) == 1
        assert verdict.audit["predicate_results"] == [{"id": key, "value": value} for key, value in values.items()]
