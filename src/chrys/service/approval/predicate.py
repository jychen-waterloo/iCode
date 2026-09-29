# Copyright (c) 2026 Chrys. All rights reserved.

"""Strict predicate assets, response validation, and fixed formal decisions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from importlib.resources import files
from typing import Any

_SCHEMA_VERSION = 1
_DECISION_VERSION = "binary-predicate-v1"
_MAX_PRINCIPLES = 32
_MAX_TEXT_LENGTH = 4_000


class PredicateAssetError(ValueError):
    """The packaged predicate asset cannot safely be used."""


class PredicateDecision(StrEnum):
    AUTO_APPROVE = "auto_approve"
    NEEDS_REVIEW = "needs_review"


@dataclass(frozen=True, slots=True)
class Principle:
    """One stable, model-evaluated semantic condition."""

    id: str
    role: str
    question: str


@dataclass(frozen=True, slots=True)
class PredicateAsset:
    """Validated immutable predicate definition used for one evaluation."""

    asset_version: str
    decision_version: str
    project: str
    digest: str
    principles: tuple[Principle, ...]

    def __post_init__(self) -> None:
        validate_asset_snapshot(self)

    @property
    def intents(self) -> tuple[Principle, ...]:
        return tuple(principle for principle in self.principles if principle.role == "intent_match")

    @property
    def risks(self) -> tuple[Principle, ...]:
        return tuple(principle for principle in self.principles if principle.role == "needs_review")


@dataclass(frozen=True, slots=True)
class PredicateValue:
    """A validated Boolean predicate result."""

    id: str
    value: bool


@dataclass(frozen=True, slots=True)
class PredicateEvaluation:
    """Result of strict parsing followed by the fixed decision table."""

    decision: PredicateDecision
    reason: str
    values: tuple[PredicateValue, ...] = ()


def load_default_asset() -> PredicateAsset:
    """Load the packaged, read-only Formal asset."""
    raw = files("chrys.service.approval").joinpath("principles.json").read_bytes()
    return parse_asset(raw)


def parse_asset(raw: bytes | str) -> PredicateAsset:
    """Validate an asset completely before exposing it to the evaluator."""
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_object)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PredicateAssetError("invalid predicate asset JSON") from exc
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "asset_version",
        "decision_version",
        "principles",
        "project",
    }:
        raise PredicateAssetError("invalid predicate asset fields")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != _SCHEMA_VERSION
        or value["decision_version"] != _DECISION_VERSION
    ):
        raise PredicateAssetError("unsupported predicate asset version")
    if not _valid_text(value["asset_version"]):
        raise PredicateAssetError("predicate asset needs an asset_version")
    if not _valid_text(value["project"]):
        raise PredicateAssetError("predicate asset needs a project owner")
    raw_principles = value["principles"]
    if not isinstance(raw_principles, list) or not raw_principles or len(raw_principles) > _MAX_PRINCIPLES:
        raise PredicateAssetError("predicate asset needs principles")
    principles: list[Principle] = []
    ids: set[str] = set()
    for item in raw_principles:
        if not isinstance(item, dict) or set(item) != {"id", "role", "question"}:
            raise PredicateAssetError("invalid principle fields")
        identifier, role, question = (
            item["id"],
            item["role"],
            item["question"],
        )
        if (
            not _valid_text(identifier)
            or identifier in ids
            or not isinstance(role, str)
            or role not in {"intent_match", "needs_review"}
            or not _valid_text(question)
        ):
            raise PredicateAssetError("invalid principle definition")
        ids.add(identifier)
        principles.append(Principle(identifier, role, question))
    roles = {principle.role for principle in principles}
    if roles != {"intent_match", "needs_review"}:
        raise PredicateAssetError("asset needs intent and review conditions")
    digest_source = raw.encode("utf-8") if isinstance(raw, str) else raw
    return PredicateAsset(
        asset_version=value["asset_version"],
        decision_version=value["decision_version"],
        project=value["project"],
        digest=asset_digest(digest_source),
        principles=tuple(principles),
    )


def validate_predicate_response(text: str, asset: PredicateAsset) -> tuple[PredicateValue, ...]:
    """Accept exactly one Boolean per principle, optionally in a JSON code fence."""
    lines = text.strip().splitlines()
    # Unwrap only one complete block; extra prose or nested blocks remain invalid.
    if len(lines) >= 3 and lines[0].strip().lower() in {"```", "```json"} and lines[-1].strip() == "```":
        text = "\n".join(lines[1:-1])
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_object)
    except (json.JSONDecodeError, PredicateAssetError) as exc:
        raise PredicateAssetError("invalid predicate response JSON") from exc
    expected = {principle.id for principle in asset.principles}
    if not isinstance(data, dict) or set(data) != expected or any(type(data[key]) is not bool for key in expected):
        raise PredicateAssetError("predicate response must contain one Boolean per required ID")
    return tuple(PredicateValue(principle.id, data[principle.id]) for principle in asset.principles)


def decide_predicates(values: tuple[PredicateValue, ...], asset: PredicateAsset) -> PredicateEvaluation:
    """Require review for any risk or a task mismatch; otherwise approve."""
    if (
        len(values) != len(asset.principles)
        or {value.id for value in values} != {principle.id for principle in asset.principles}
        or any(type(value.value) is not bool for value in values)
    ):
        raise PredicateAssetError("invalid predicate values")
    by_id = {value.id: value for value in values}
    triggered = [
        principle.id
        for principle in asset.principles
        if (principle.role == "needs_review" and by_id[principle.id].value)
        or (principle.role == "intent_match" and not by_id[principle.id].value)
    ]
    if triggered:
        return PredicateEvaluation(
            PredicateDecision.NEEDS_REVIEW, f"Requires human review: {', '.join(triggered)}.", values
        )
    return PredicateEvaluation(
        PredicateDecision.AUTO_APPROVE, "All task intent conditions are met without review risks.", values
    )


def evaluate_predicate_response(text: str, asset: PredicateAsset) -> PredicateEvaluation:
    """Shared, side-effect-free online/offline predicate evaluation entry point."""
    return decide_predicates(validate_predicate_response(text, asset), asset)


def asset_digest(raw: bytes) -> str:
    """Return a stable audit identifier for a candidate or packaged asset."""
    return hashlib.sha256(raw).hexdigest()


def validate_asset_snapshot(asset: PredicateAsset) -> None:
    """Validate once when constructing the immutable asset."""
    if (
        asset.decision_version != _DECISION_VERSION
        or not _valid_text(asset.asset_version)
        or not _valid_text(asset.project)
        or not isinstance(asset.digest, str)
        or len(asset.digest) != 64
        or any(character not in "0123456789abcdef" for character in asset.digest)
        or not isinstance(asset.principles, tuple)
        or not 2 <= len(asset.principles) <= _MAX_PRINCIPLES
        or any(
            not isinstance(principle, Principle)
            or not _valid_text(principle.id)
            or principle.role not in {"intent_match", "needs_review"}
            for principle in asset.principles
        )
        or len({principle.id for principle in asset.principles}) != len(asset.principles)
        or {principle.role for principle in asset.principles} != {"intent_match", "needs_review"}
        or any(not _valid_text(principle.question) for principle in asset.principles)
    ):
        raise PredicateAssetError("invalid Formal asset snapshot")


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PredicateAssetError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _valid_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= _MAX_TEXT_LENGTH
