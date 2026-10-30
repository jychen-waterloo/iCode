# Structured Shell Pre-Judge

iCode can optionally inspect Bash commands with a structured parser and CEL policy before the usual tool approval. It is **off by default**. The original approval rules, existing hooks, remembered grants, and the final Shell Command Filter remain in place.

Place `prejudge.yaml` in the user configuration directory (`~/.chrys/` on macOS/Linux; the iCode user configuration directory on Windows). Workspace files do not configure this feature.

```yaml
schema_version: 1
mode: "shadow"
policy_id: example-v1
rules:
  - id: block-rm
    effect: block
    target: command
    when: 'prefix.size() > 0 && prefix[0] == "rm"'
  - id: allow-git-status
    effect: allow
    target: command
    when: 'argv == ["git", "status"]'
```

The mode must be quoted: YAML interprets unquoted `off` as a Boolean. `off` retains the original behavior; `shadow` logs suggested decisions but does not enforce them; `enforce` blocks matching commands, allows fully covered commands when existing mandatory guards permit, and otherwise continues the ordinary approval process. Explicit BYPASS does not apply Pre-Judge BLOCK rules. Headless `icode run` and `icode workflow run` use BYPASS, so these rules do not protect those executions.

Only Bash and Git Bash are supported. Other shells, including zsh, dash, sh, PowerShell, and cmd.exe, are not automatically parsed as Bash. In enforce mode, unsupported commands defer to regular approval (without the legacy readonly shortcut); this can increase approval prompts. Dynamic commands, redirects, globs, and most control-flow forms are never automatically allowed. Recognizable static commands inside unsupported syntax can still match a block rule, but the feature is not a complete shell security boundary.

When enabled, the experimental feature requires the optional `tree-sitter==0.25.1`, `tree-sitter-bash==0.25.1`, and `cel-expr-python==0.1.3` packages. The CEL wheel does not cover the project's older glibc 2.17 offline Linux distribution target. Invalid enforce configuration or missing parser/CEL support causes a configuration error rather than silently disabling enforcement. Invalid shadow configuration or unavailable dependencies disable shadow observation with a logged warning. Runtime parser failures defer to ordinary approval. The platform support and complete integration test gates remain under review.

Wrapper commands such as `command rm`, `env rm`, or `time rm` are opaque in this version; a BLOCK rule matching only `prefix[0] == "rm"` does not match them. They defer rather than being automatically approved.
