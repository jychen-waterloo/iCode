# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Conservative AST/CEL pre-judge; independent of the legacy shell filter.

This module never executes or rewrites a command. Unsupported or incomplete
syntax cannot yield ALLOW. Optional dependencies are imported only when an
enabled policy is loaded.
"""
from __future__ import annotations

import hashlib
import shlex
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml


class Route(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    DEFER = "defer"


@dataclass(frozen=True, slots=True)
class CommandNode:
    source_span: tuple[int, int]
    argv: tuple[str, ...] | None
    prefix: tuple[str, ...]
    text: str


@dataclass(frozen=True, slots=True)
class Analysis:
    syntax_valid: bool
    coverage_complete: bool
    executable_nodes: tuple[CommandNode, ...]
    unsupported: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PreJudgeResult:
    route: Route
    reason_code: str
    matched_rule_ids: tuple[str, ...]
    matched_node_spans: tuple[tuple[int, int], ...]
    policy_id: str
    analysis_digest: str


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    effect: Route
    expression: Any


@dataclass(frozen=True, slots=True)
class Policy:
    mode: str
    policy_id: str
    rules: tuple[Rule, ...]


_OPAQUE = frozenset({
    "eval", ".", "source", "exec", "builtin", "trap", "xargs",
    "sudo", "timeout", "nice", "nohup", "bash", "sh", "dash", "find",
})
_DYNAMIC = frozenset({
    "expansion", "simple_expansion", "command_substitution",
    "process_substitution", "arithmetic_expansion", "variable_assignment",
    "heredoc_redirect", "heredoc_body", "here_string",
})
_CONTAINERS = frozenset({
    "program", "list", "pipeline", "compound_statement", "subshell",
})
_QUOTED = frozenset({"string", "raw_string", "ansi_c_string", "word", "concatenation", "command_name"})


def _digest(command: str, dialect: str) -> str:
    return hashlib.sha256((dialect + "\x00" + command).encode("utf-8")).hexdigest()


def _dynamic(node: Any) -> bool:
    if node.type in _DYNAMIC or node.type in {"ERROR", "MISSING"} or node.is_missing:
        return True
    return any(_dynamic(child) for child in node.named_children)


def _parse_command(node: Any, data: bytes) -> CommandNode:
    text = data[node.start_byte:node.end_byte].decode("utf-8")
    # Conservative token collection: a dynamic word terminates the reliable
    # static prefix; it must never be reconstructed into an allowable argv.
    words = [child for child in node.named_children if child.type in _QUOTED]
    if not words or any(child.type not in _QUOTED for child in node.named_children):
        return CommandNode((node.start_byte, node.end_byte), None, (), text)
    prefix: list[str] = []
    complete = True
    for word in words:
        if _dynamic(word):
            complete = False
            break
        try:
            token = shlex.split(data[word.start_byte:word.end_byte].decode("utf-8"), posix=True)
        except ValueError:
            complete = False
            break
        if len(token) != 1:
            complete = False
            break
        prefix.append(token[0])
    return CommandNode(
        (node.start_byte, node.end_byte),
        tuple(prefix) if complete else None,
        tuple(prefix),
        text,
    )


def analyze(command: str, *, dialect: str = "bash") -> Analysis:
    if dialect not in {"bash", "git_bash"}:
        return Analysis(False, False, (), ("unsupported_dialect",))
    data = command.encode("utf-8")
    if len(data) > 65536:
        return Analysis(False, False, (), ("limit_exceeded",))
    try:
        import tree_sitter_bash
        from tree_sitter import Language, Parser
    except ImportError as exc:
        raise RuntimeError("Enable the optional pre-judge dependencies first") from exc
    tree = Parser(Language(tree_sitter_bash.language())).parse(data)
    root = tree.root_node
    if root.has_error:
        return Analysis(False, False, (), ("parse_error",))
    nodes: list[CommandNode] = []
    unsupported: list[str] = []
    pending = [(root, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > 20000 or depth > 128:
            return Analysis(True, False, tuple(nodes), ("limit_exceeded",))
        if node.type == "command":
            nodes.append(_parse_command(node, data))
            continue
        if node.type in _CONTAINERS:
            pending.extend((child, depth + 1) for child in reversed(node.named_children))
        elif node.type != "comment":
            unsupported.append(node.type)
    nodes.sort(key=lambda item: item.source_span)
    if not nodes:
        unsupported.append("no_commands")
    if any(n.argv is None for n in nodes):
        unsupported.append("dynamic_word")
    if any(n.prefix and n.prefix[0] in _OPAQUE for n in nodes):
        unsupported.append("opaque_carrier")
    return Analysis(True, not unsupported, tuple(nodes), tuple(dict.fromkeys(unsupported)))


def _cel_env() -> Any:
    try:
        from cel_expr_python import cel
    except ImportError as exc:
        raise RuntimeError(
            "Enabled pre-judge requires cel-expr-python==0.1.3; "
            "its Linux wheels are not compatible with glibc 2.17"
        ) from exc
    # CEL's expression engine provides checked expressions and no Python
    # evaluation, file, process or network functions.
    return cel.NewEnv(variables={
        "argv": cel.Type.list(cel.Type.STRING),
        "prefix": cel.Type.list(cel.Type.STRING),
    })


def load_policy(path: Path) -> Policy:
    if not path.exists():
        return Policy("off", "", ())
    content = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(content, dict) or set(content) - {
        "schema_version", "mode", "policy_id", "rules"
    }:
        raise ValueError("Invalid pre-judge configuration")
    if type(content.get("schema_version")) is not int or content["schema_version"] != 1:
        raise ValueError("Invalid pre-judge schema_version")
    mode = content.get("mode")
    if mode not in ("off", "shadow", "enforce"):
        raise ValueError("mode must be quoted 'off', 'shadow', or 'enforce'")
    if mode == "off":
        return Policy("off", "", ())
    ident = content.get("policy_id")
    raw_rules = content.get("rules")
    if not isinstance(ident, str) or not ident or not isinstance(raw_rules, list) or len(raw_rules) > 1000:
        raise ValueError("Invalid pre-judge policy_id or rules")
    env = _cel_env()
    rules: list[Rule] = []
    seen: set[str] = set()
    for raw in raw_rules:
        if not isinstance(raw, dict) or set(raw) != {"id", "effect", "target", "when"}:
            raise ValueError("Invalid pre-judge rule fields")
        rid, effect, target, when = (raw[key] for key in ("id", "effect", "target", "when"))
        if not isinstance(rid, str) or not rid or rid in seen:
            raise ValueError("Duplicate or invalid pre-judge rule ID")
        if effect not in ("allow", "block") or target != "command":
            raise ValueError("Invalid pre-judge effect or target")
        if not isinstance(when, str) or not when or len(when) > 4096:
            raise ValueError("Invalid CEL expression")
        expression = env.compile(f"({when}) && true")
        # The trailing boolean conjunction forces CEL to statically check
        # the policy's when expression as a boolean at load time.
        seen.add(rid)
        rules.append(Rule(rid, Route(effect), expression))
    return Policy(mode, ident, tuple(rules))


def route(command: str, dialect: str, policy: Policy) -> PreJudgeResult:
    digest = _digest(command, dialect)
    if policy.mode == "off":
        return PreJudgeResult(Route.DEFER, "off", (), (), policy.policy_id, digest)
    analysis = analyze(command, dialect=dialect)
    matched: list[str] = []
    spans: list[tuple[int, int]] = []
    all_allowed = analysis.coverage_complete
    for node in analysis.executable_nodes:
        allowed = False
        for rule in policy.rules:
            # Incomplete argv can be used for a confirmed block through its
            # static prefix, but never for an ALLOW decision.
            if rule.effect is Route.ALLOW and node.argv is None:
                continue
            try:
                verdict = rule.expression.eval(data={
                    "argv": list(node.argv or ()),
                    "prefix": list(node.prefix),
                })
                match = verdict.value() is True
            except Exception:
                match = False
            if match:
                matched.append(rule.id)
                spans.append(node.source_span)
                if rule.effect is Route.BLOCK:
                    return PreJudgeResult(Route.BLOCK, "matched_block", tuple(matched), tuple(spans), policy.policy_id, digest)
                allowed = True
        if not allowed:
            all_allowed = False
    if all_allowed:
        return PreJudgeResult(Route.ALLOW, "all_units_allowed", tuple(matched), tuple(spans), policy.policy_id, digest)
    return PreJudgeResult(
        Route.DEFER, analysis.unsupported[0] if analysis.unsupported else "unmatched_unit",
        tuple(matched), tuple(spans), policy.policy_id, digest,
    )
