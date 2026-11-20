# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Certify a small subset of the pinned Zsh and PowerShell concrete grammars.

Check all children, including anonymous punctuation, and the source between
them. A new grammar production, ignored token or unknown separator cannot
silently expand the certified subset.
"""

from __future__ import annotations

import logging
import ntpath
import re
from collections.abc import Callable
from functools import lru_cache
from importlib.metadata import version
from typing import TYPE_CHECKING

from chrys.foundation.platform import get_platform

from ._analysis import Analysis, CommandNode, covered

if TYPE_CHECKING:
    from tree_sitter import Language, Node

logger = logging.getLogger(__name__)
ADAPTED_DIALECTS = frozenset({"zsh", "powershell", "pwsh"})
_HORIZONTAL = b" \t"
_LAYOUT = b" \t\r\n"
_ZSH_WORD = re.compile(rb"[a-zA-Z0-9_./+,:@%-]+")
_PS_BARE = re.compile(rb"[a-zA-Z0-9_./+,:\\-]+")
_PS_PARAMETER = re.compile(rb"--?[a-zA-Z][a-zA-Z0-9-]*")
_PS_DECIMAL = re.compile(rb"(?:0|[1-9][0-9]{0,8})")
_POSIX_EXE = re.compile(r"(?:/[a-zA-Z0-9_.+-]+)+")
_WINDOWS_EXE = re.compile(r"[A-Za-z]:[\\/](?:[a-zA-Z0-9_.+-]+[\\/])*[a-zA-Z0-9_.+-]+\.exe", re.IGNORECASE)


@lru_cache(maxsize=2)
def _language(grammar: str) -> Language | None:
    try:
        from tree_sitter import Language

        if grammar == "zsh":
            if version("tree-sitter-zsh") != "0.64.3":
                raise ValueError("Zsh Pre-Judge requires tree-sitter-zsh==0.64.3")
            import tree_sitter_zsh

            return Language(tree_sitter_zsh.language())
        if version("tree-sitter-pwsh") != "0.38.1":
            raise ValueError("PowerShell Pre-Judge requires tree-sitter-pwsh==0.38.1")
        import tree_sitter_pwsh

        return Language(tree_sitter_pwsh.language())
    except ImportError, RuntimeError, TypeError, ValueError:
        logger.warning("Pre-Judge grammar %s unavailable; deferring this dialect", grammar, exc_info=True)
        return None


def _raw(node: Node, data: bytes) -> bytes:
    return data[node.start_byte : node.end_byte]


def _zsh_word(node: Node, data: bytes) -> bytes | None:
    raw = _raw(node, data)
    if node.type in {"word", "number"} and not node.children and _ZSH_WORD.fullmatch(raw):
        return raw
    if len(raw) < 2 or not all(32 <= byte <= 126 for byte in raw):
        return None
    inner = raw[1:-1]
    if (
        node.type == "raw_string"
        and raw[:1] == raw[-1:] == b"'"
        and b"'" not in inner
        and all(child.type == "'" and not child.is_named for child in node.children)
    ):
        return inner
    if (
        node.type == "string"
        and raw[:1] == raw[-1:] == b'"'
        and not any(c in inner for c in b'"$\\`')
        and all(child.type in {'"', "string_content"} and not child.children for child in node.children)
    ):
        return inner
    return None


def _zsh_command(node: Node, data: bytes) -> tuple[str, ...] | None:
    children = node.children
    if (
        not children
        or children[0].type != "command_name"
        or [child.type for child in children[0].children] != ["word"]
        or _raw(children[0], data) != _raw(children[0].children[0], data)
        or not covered(node, data, _HORIZONTAL)
    ):
        return None
    words = [children[0].children[0], *children[1:]]
    tokens: list[str] = []
    for index, word in enumerate(words):
        field = "name" if index == 0 else "argument"
        if node.field_name_for_child(index) != field or (index and children[index - 1].end_byte == word.start_byte):
            return None
        value = _zsh_word(word, data)
        if value is None or b"!" in value:
            return None
        tokens.append(value.decode("ascii"))
    return tuple(tokens)


def _ps_argument(node: Node, data: bytes) -> bytes | None:
    raw = _raw(node, data)
    if node.type == "generic_token" and not node.children and _PS_BARE.fullmatch(raw):
        return raw
    if node.type == "command_parameter" and not node.children and _PS_PARAMETER.fullmatch(raw):
        return raw
    if node.type != "unary_expression" or len(node.children) != 1:
        return None
    value = node.children[0]
    if _raw(value, data) != raw:
        return None
    children = [child.type for child in value.children]
    if value.type == "integer_literal" and children == ["decimal_integer_literal"] and _PS_DECIMAL.fullmatch(raw):
        return raw
    if value.type != "string_literal" or len(value.children) != 1:
        return None
    literal = value.children[0]
    if _raw(literal, data) != raw:
        return None
    if (
        literal.type == "verbatim_string_characters"
        and not literal.children
        and re.fullmatch(rb"'(?:[ -&(-~]|'')*'", raw)
    ):
        return raw[1:-1].replace(b"''", b"'")
    if (
        literal.type == "expandable_string_literal"
        and all(child.type in {'"', '""'} and not child.is_named for child in literal.children)
        and re.fullmatch(rb'"(?:[ -!#%&\x27-\x5f\x61-\x7e]|"")*"', raw)
    ):
        return raw[1:-1].replace(b'""', b'"')
    return None


def _ps_command(node: Node, data: bytes) -> tuple[str, ...] | None:
    children = node.children
    if [child.type for child in children] not in (["command_name"], ["command_name", "command_elements"]):
        return None
    name = children[0]
    if name.children or not _PS_BARE.fullmatch(_raw(name, data)) or not covered(node, data, _HORIZONTAL):
        return None
    tokens = [_raw(name, data).decode("ascii")]
    if len(children) == 2:
        elements = children[1]
        if not elements.children or not covered(elements, data, _HORIZONTAL):
            return None
        separated = False
        for child in elements.children:
            if (
                child.type == "command_argument_sep"
                and not _raw(child, data).strip(_HORIZONTAL)
                and all(not part.is_named and _raw(part, data) in (b" ", b"\t") for part in child.children)
            ):
                separated = True
                continue
            value = _ps_argument(child, data)
            if not separated or value is None:
                return None
            tokens.append(value.decode("ascii"))
            separated = False
    return tuple(tokens)


def _pipeline(node: Node, data: bytes) -> list[Node] | None:
    if not covered(node, data, _HORIZONTAL):
        return None
    commands = []
    for index, child in enumerate(node.children):
        if index % 2 == 0 and child.type == "command":
            commands.append(child)
        elif index % 2 == 0 or child.type != "|" or _raw(child, data) != b"|":
            return None
    return commands if len(node.children) % 2 == 1 else None


def _statements(node: Node, data: bytes, *, zsh: bool) -> list[Node] | None:
    commands: list[Node] = []
    terminated = True
    offset = node.start_byte
    if not covered(node, data, _LAYOUT):
        return None
    for child in node.children:
        terminated |= b"\n" in data[offset : child.start_byte]
        offset = child.end_byte
        if child.type == (";" if zsh else "empty_statement") and _raw(child, data) == b";":
            terminated = True
            continue
        if not terminated:
            return None
        if zsh and child.type == "command":
            commands.append(child)
        elif child.type == "pipeline":
            if not zsh:
                if [part.type for part in child.children] != ["pipeline_chain"] or not covered(
                    child, data, _HORIZONTAL
                ):
                    return None
                child = child.children[0]
            pipeline = _pipeline(child, data)
            if pipeline is None:
                return None
            commands.extend(pipeline)
        else:
            return None
        terminated = False
    return commands


def analyze_adapted(data: bytes, *, dialect: str) -> Analysis:
    """Extract argv only when all executable source is accounted for."""
    zsh = dialect == "zsh"
    language = _language("zsh" if zsh else "pwsh")
    if language is None:
        return Analysis(False, False, (), ("grammar_unavailable",))
    try:
        from tree_sitter import Parser

        root = Parser(language).parse(data).root_node
    except ImportError, RuntimeError, TypeError, ValueError:
        logger.warning("Pre-Judge parser failed for %s; deferring", dialect, exc_info=True)
        return Analysis(False, False, (), ("parse_error",))
    if root.has_error:
        return Analysis(False, False, (), ("parse_error",))
    if root.type != "program" or (data[: root.start_byte] + data[root.end_byte :]).strip(_LAYOUT):
        return Analysis(True, False, (), ("unsupported_construct",))
    statements = root
    if not zsh:
        if [child.type for child in root.children] != ["statement_list"] or not covered(root, data, _LAYOUT):
            return Analysis(True, False, (), ("unsupported_construct",))
        statements = root.children[0]
    commands = _statements(statements, data, zsh=zsh)
    if not commands:
        return Analysis(True, False, (), ("unsupported_construct",))
    extract: Callable[[Node, bytes], tuple[str, ...] | None] = _zsh_command if zsh else _ps_command
    nodes = []
    for node in commands:
        argv = extract(node, data)
        if argv is None:
            return Analysis(True, False, tuple(nodes), ("unsupported_argument",))
        nodes.append(CommandNode((node.start_byte, node.end_byte), argv, argv, _raw(node, data).decode("ascii")))
    return Analysis(True, True, tuple(nodes), ())


def explicit_executable(argv: tuple[str, ...], dialect: str) -> bool:
    """Require a literal executable path; bare names depend on shell resolution."""
    head = argv[0]
    windows_ps = dialect == "powershell" or (dialect == "pwsh" and get_platform().is_windows)
    if windows_ps:
        # Windows PowerShell 5.1's native argument handling can drop empty
        # strings or consume quotes. Limit both Windows editions to the common subset.
        if any(not arg or '"' in arg or (" " in arg and arg.endswith("\\")) for arg in argv[1:]):
            return False
        return bool(_WINDOWS_EXE.fullmatch(head)) and not ntpath.isreserved(head[2:].lstrip("\\/"))
    return bool(_POSIX_EXE.fullmatch(head)) and not {".", ".."}.intersection(head.split("/"))
