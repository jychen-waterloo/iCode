# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Conservative AST/CEL pre-judge; independent of the legacy shell filter.

This module never executes or rewrites a command. Unsupported or incomplete
syntax cannot yield ALLOW. Optional dependencies are imported only when an
enabled policy is loaded.
"""
from __future__ import annotations

import hashlib
import logging
import shlex
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


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


_OPAQUE = frozenset(
    {
        ".", "bash", "builtin", "chrt", "command", "dash", "doas", "env",
        "eval", "exec", "find", "ionice", "nice", "nohup", "sh", "source",
        "stdbuf", "su", "sudo", "time", "timeout", "trap", "xargs",
    }
)
_DYNAMIC = frozenset({
    "brace_expression", "glob_pattern", "extglob_pattern", "word_expansion",
    "expansion", "simple_expansion", "command_substitution",
    "process_substitution", "arithmetic_expansion", "variable_assignment",
    "heredoc_redirect", "heredoc_body", "here_string",
})
_CONTAINERS = frozenset({
    "program", "list", "pipeline", "compound_statement", "subshell",
})
_QUOTED = frozenset({"string", "raw_string", "ansi_c_string", "word", "concatenation", "command_name"})


def _digest(command: str, dialect: str) -> str:
    return hashlib.sha256((dialect + "\x00" + command).encode("utf-8", errors="surrogatepass")).hexdigest()


def _dynamic(node: Any) -> bool:
    if node.type in _DYNAMIC or node.type in {"ERROR", "MISSING"} or node.is_missing:
        return True
    return any(_dynamic(child) for child in node.named_children)


def _parse_command(node: Any, data: bytes) -> CommandNode:
    text = data[node.start_byte:node.end_byte].decode("utf-8")
    head = node.child_by_field_name("name")
    if head is None:
        return CommandNode((node.start_byte, node.end_byte), None, (), text)
    words = [head]
    # Collect only ordered literal arguments. Assignment/redirect nodes are
    # not argv, but a reliable head can still trigger a block.
    for child in node.named_children:
        if child.id == head.id:
            continue
        if child.type in _QUOTED:
            words.append(child)
    prefix: list[str] = []
    complete = all(child.type in _QUOTED or child.id == head.id for child in node.named_children)
    for word in words:
        if _dynamic(word):
            complete = False
            break
        raw = data[word.start_byte:word.end_byte].decode("utf-8")
        if any(ch in raw for ch in "*?[") and word.type in {"word", "command_name"}:
            complete = False
            break
        try:
            token = shlex.split(raw, posix=True)
        except ValueError:
            complete = False
            break
        if len(token) != 1:
            complete = False
            break
        prefix.append(token[0])
    return CommandNode(
        (node.start_byte, node.end_byte),
        tuple(prefix) if complete else None, tuple(prefix), text,
    )


@lru_cache(maxsize=1)
def _language() -> Any:
    import tree_sitter_bash
    from tree_sitter import Language
    return Language(tree_sitter_bash.language())


def analyze(command: str, *, dialect: str = "bash") -> Analysis:
    if dialect not in {"bash", "git_bash"}:
        return Analysis(False, False, (), ("unsupported_dialect",))
    try:
        data = command.encode("utf-8")
    except UnicodeError:
        return Analysis(False, False, (), ("parse_error",))
    if len(data) > 65536:
        return Analysis(False, False, (), ("limit_exceeded",))
    try:
        from tree_sitter import Parser
    except ImportError as exc:
        raise RuntimeError("Enable the optional pre-judge dependencies first") from exc
    tree = Parser(_language()).parse(data)
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
            if any(c.type not in _QUOTED and c.type != "command_name" for c in node.named_children):
                unsupported.append("unsupported_construct")
            # Substitutions inside arguments may contain executable nodes;
            # their presence makes the whole command ineligible for ALLOW.
            for child in reversed(node.named_children):
                if _dynamic(child):
                    unsupported.append("dynamic_word")
                    pending.extend((c, depth + 1) for c in reversed(child.named_children))
            continue
        if node.type not in _CONTAINERS and node.type != "comment":
            unsupported.append(node.type)
        # Descend into unsupported wrappers for reliable BLOCK evidence.
        pending.extend((child, depth + 1) for child in reversed(node.named_children))
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


def _ensure_bash_parser() -> None:
    """Fail during configuration, not at the first shell invocation."""
    try:
        from tree_sitter import Parser

        Parser(_language())
    except Exception as exc:
        raise RuntimeError(
            "Enabled pre-judge requires tree-sitter==0.25.1 and "
            "tree-sitter-bash==0.25.1 with a compatible Bash grammar"
        ) from exc


def _compile_enabled_policy(content: dict[str, Any], mode: str) -> Policy:
    ident = content.get("policy_id")
    raw_rules = content.get("rules")
    if not isinstance(ident, str) or not ident or not isinstance(raw_rules, list) or len(raw_rules) > 1000:
        raise ValueError("Invalid pre-judge policy_id or rules")
    _ensure_bash_parser()
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
        # CEL statically checks the expression as Boolean at load time.
        seen.add(rid)
        rules.append(Rule(rid, Route(effect), expression))
    return Policy(mode, ident, tuple(rules))


def load_policy(path: Path) -> Policy:
    if not path.exists():
        return Policy("off", "", ())
    content: Any = None
    try:
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
        return _compile_enabled_policy(content, mode)
    except Exception:
        # A *declared* shadow policy has no enforcement authority. Bad
        # rules/missing optional deps must not prevent iCode from starting.
        # Unknown or malformed mode is NOT silently interpreted as shadow.
        if isinstance(content, dict) and content.get("mode") == "shadow":
            logger.warning("Invalid shadow pre-judge policy; disabling observation", exc_info=True)
            return Policy("off", "", ())
        raise

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
                logger.warning("CEL evaluation failed for rule %s", rule.id, exc_info=True)
                all_allowed = False
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
