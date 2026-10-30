# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Conservative routing rules: block precedence, partial coverage and OFF."""
from __future__ import annotations

import pytest
from chrys.service.approval import prejudge_v2 as pj


class Verdict:
    def __init__(self, match): self.match = match
    def type(self): return "BOOL"
    def value(self): return self.match


class Expression:
    def __init__(self, test): self.test = test
    def eval(self, *, data): return Verdict(self.test(data))


def policy(*rules):
    return pj.Policy("enforce", "pilot", tuple(rules))


def command(argv, prefix=None):
    return pj.CommandNode((0, 12), tuple(argv) if argv is not None else None,
                          tuple(prefix if prefix is not None else (argv or ())), "")


def test_block_precedes_allow(monkeypatch):
    monkeypatch.setattr(pj, "analyze", lambda *a, **kw: pj.Analysis(
        True, True, (command(["echo", "rm"]), command(["rm", "file"])), ()))
    rules = policy(
        pj.Rule("A-echo", pj.Route.ALLOW, Expression(lambda d: d["argv"][0] == "echo")),
        pj.Rule("B-rm", pj.Route.BLOCK, Expression(lambda d: d["prefix"][0] == "rm")),
    )
    assert pj.route("echo rm; rm file", "bash", rules).route is pj.Route.BLOCK


def test_unknown_requires_defer(monkeypatch):
    monkeypatch.setattr(pj, "analyze", lambda *a, **kw: pj.Analysis(
        True, True, (command(["git", "status"]), command(["unknown"])), ()))
    rules = policy(pj.Rule("git", pj.Route.ALLOW, Expression(lambda d: d["argv"] == ["git", "status"])))
    assert pj.route("git status && unknown", "bash", rules).route is pj.Route.DEFER


def test_dynamic_prefix_only_blocks(monkeypatch):
    monkeypatch.setattr(pj, "analyze", lambda *a, **kw: pj.Analysis(
        True, False, (command(None, ["rm"]),), ("dynamic_word",)))
    a = pj.Rule("allow", pj.Route.ALLOW, Expression(lambda d: True))
    b = pj.Rule("block", pj.Route.BLOCK, Expression(lambda d: d["prefix"] == ["rm"]))
    assert pj.route('rm "$X"', "bash", policy(a)).route is pj.Route.DEFER
    assert pj.route('rm "$X"', "bash", policy(b)).route is pj.Route.BLOCK


def test_unsupported_never_allows(monkeypatch):
    monkeypatch.setattr(pj, "analyze", lambda *a, **kw: pj.Analysis(
        True, False, (command(["echo", "ok"]),), ("command_substitution",)))
    a = pj.Rule("allow", pj.Route.ALLOW, Expression(lambda d: True))
    assert pj.route('echo "$(rm f)"', "bash", policy(a)).route is pj.Route.DEFER


def test_off_and_missing_config(tmp_path):
    assert pj.route("ignored", "bash", pj.Policy("off", "", ())).route is pj.Route.DEFER
    assert pj.load_policy(tmp_path / "missing.yaml").mode == "off"


@pytest.mark.parametrize("config", [
    "schema_version: 1\nmode: off\npolicy_id: test\nrules: []",
    'schema_version: 1\nmode: "enfroce"\npolicy_id: test\nrules: []',
    'schema_version: 1\nmode: "off"\nunknown: true',
])
def test_invalid_config(tmp_path, config):
    file = tmp_path / "prejudge.yaml"
    file.write_text(config, encoding="utf-8")
    with pytest.raises(ValueError):
        pj.load_policy(file)
