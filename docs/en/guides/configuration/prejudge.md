# Structured Pre-Judge (PR1, experimental)

The optional AST/CEL router is separate from legacy regex/readonly routing,
DAA, the LLM Judge, before-tool hooks and the post-tool shell filter.
The default is off. The policy file is the trusted user configuration
directory's prejudge.yaml (on Unix: ~/.chrys/prejudge.yaml).
Workspace files are not consulted.

Modes: "off" keeps legacy behavior; "shadow" evaluates without changing
approval decisions; "enforce" blocks a definite BLOCK and short-circuits a
definite ALLOW only after mandatory sensitive-target checks. DEFER is routed
to ordinary approval without the legacy readonly shortcut.

Example YAML (quote the mode; an unquoted 'off' is a YAML boolean):

    schema_version: 1
    mode: "enforce"
    policy_id: basic-pilot-v1
    rules:
      - id: B-rm
        effect: block
        target: command
        when: 'prefix.size() > 0 && prefix[0] == "rm"'
      - id: A-status
        effect: allow
        target: command
        when: 'argv == ["git", "status"]'

Dependencies must be explicitly installed when enabled:
tree-sitter==0.25.1, tree-sitter-bash==0.25.1,
cel-expr-python==0.1.3. The official CEL Linux wheels require a glibc
version newer than the offline Linux release floor of 2.17. Do not make this
a required dependency before verifying the release matrix.

This branch remains experimental and is not a completed PR1 release:
CEL compile-time Boolean checking, full syntax corpus, post-human-hook
reapproval, distribution gates and full regression tests remain open.
