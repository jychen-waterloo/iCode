# Structured Shell Pre-Judge

iCode can optionally inspect Bash, Zsh, and PowerShell commands using Tree-sitter and literal YAML rules before ordinary tool approval. It is **off by default** and returns only **ALLOW** or **DEFER**. ALLOW offers an automatic-approval shortcut. DEFER continues through existing approval. Existing Hooks, approval policy, the read-only shortcut, remembered grants, and the **pre-execution** Shell Command Filter still apply.

Place `prejudge.yaml` in iCode's trusted user configuration directory (`~/.chrys/prejudge.yaml` on macOS/Linux). Workspace files do not provide rules.

```yaml
schema_version: 1
mode: "shadow"
policy_id: example-v1
rules:
  - id: allow-git-status
    effect: allow
    target: command
    match:
      argv_exact: [git, status]
  - id: allow-echo
    effect: allow
    target: command
    match:
      argv_first: [echo]
```

### Matcher reference

Each rule uses `effect: allow`, `target: command`, and exactly **one** top-level matcher from this closed set of two literal matchers. DEFER is the default when a command cannot be allowed; it is not a configured rule effect. Regex, logical operators, CLI schemas, and other matcher names are not supported:

| Matcher | Meaning | Allowed effects |
| --- | --- | --- |
| `argv_exact: [git, status]` | Full literal argument vector equals exactly the given non-empty sequence | ALLOW |
| `argv_first: [echo]` | First token of the complete literal argument vector equals the given token | **ALLOW only** |

Matchers require **lists of non-empty literal strings**, even when there is only one token. An ALLOW rule using `argv_first: [git]` would grant *all* Git subcommands with complete static arguments, including mutating ones; prefer `argv_exact` for commands with risk-bearing arguments. Unknown keys, multiple matcher fields, empty lists, and non-string values are rejected during policy loading. The removed `effect: block` and `prefix_first` are rejected rather than silently ignored; remove those rules from older configurations. The policy schema version is `1`.

### Decision safety

A structured ALLOW requires **every executable AST node** to match an ALLOW rule, complete static argv and full supported syntax coverage. Anything unmatched, malformed, dynamic, or unsupported returns DEFER. DEFER continues through existing approval, including its read-only shortcut and sensitive-data checks. For example, `rm x` without an ALLOW rule enters ordinary approval; Pre-Judge does not reject it. Existing read-only approvals such as `ls *.py`, `ls 2>/dev/null`, and `sort f` still work, including with `rules: []`. A static prefix alone never justifies ALLOW. In `echo "rm"`, `rm` is an argument rather than another executable.

Use `mode: "off"`, `mode: "shadow"`, or `mode: "enforce"`. Unquoted `mode: off` (parsed by YAML as `False`), `mode: false`, and an empty file also disable the feature without loading Tree-sitter. `shadow` logs proposed ALLOW/DEFER decisions without acting on them; `enforce` applies eligible ALLOW shortcuts. Malformed YAML **syntax** raises a path-qualified error at ordinary approval startup, even if the intended mode was `shadow`. Parseable `shadow` YAML with invalid rules or dependencies instead warns (with the file path and rule ID where applicable) and disables observation. Invalid `enforce` rules fail with the file path and rule ID. A BYPASS run does not load or validate `prejudge.yaml`; if approval mode later changes to MANUAL/AUTO, the policy is loaded then.

### Shells, syntax, and executable identity

| Shell | Tree-sitter grammar | Supported syntax |
| --- | --- | --- |
| Bash / Git Bash | `tree-sitter-bash==0.25.1` | Static Bash argv, quoting, pipelines, and supported compound commands. Existing Bash rules keep their behavior. |
| Zsh | `tree-sitter-zsh==0.64.3` | Simple commands, bare arguments, single and double quoted literals, independent statements, and simple pipelines. |
| Windows PowerShell 5.1 (`powershell`) and PowerShell 7+ (`pwsh`) | `tree-sitter-pwsh==0.38.1` | Simple commands, literal arguments, separate parameter tokens such as `-LiteralPath`, independent statements, and simple pipelines. |

For Zsh and PowerShell, a matching rule also needs a **literal absolute path to a trusted executable** for every command. On Windows PowerShell and Windows `pwsh`, use a drive-qualified `.exe` path. For example, use `argv_exact: ['/usr/bin/git', status]` on Zsh or `argv_exact: ['C:/Windows/System32/whoami.exe', /user]` on Windows. Matching is case-sensitive and compares the literal path spelling, even when the shell resolves names case-insensitively. Use a path you control or trust.

Zsh `git status` and PowerShell `Get-Content -LiteralPath README.md` have static arguments but DEFER because the executable or cmdlet identity is unresolved. A bare name can resolve to an alias, a function, a cmdlet, or a program on PATH. A structured ALLOW in these dialects starts the shell without user startup files or profiles. Zsh still reads the system `zshenv`; the gate assumes the installed shell and system startup configuration are trusted and honor the startup flags.

The Zsh and PowerShell adapters accept a conservative ASCII literal subset. Dynamic expansion, Zsh glob qualifiers, option-dependent patterns and history expansion, PowerShell splatting, invocation operators and script blocks, redirections, and parse errors DEFER. PowerShell also defers Windows native arguments whose quoting differs across versions. Unsupported shells such as `sh`, `dash`, `fish`, and `cmd.exe` continue through existing approval.

**Dependencies:** install `tree-sitter==0.25.1` and the pinned Bash grammar into the Python environment running iCode to enable Pre-Judge. Install the corresponding Zsh or PowerShell grammar to use that adapter. An unavailable or incompatible additional grammar causes that dialect to DEFER. The optional grammars have Python 3.14-compatible wheels for Linux, macOS, and Windows. The standard wheel and offline distribution omit these optional packages. `uv sync` installs them for development, and `off` mode does not load them.

### Approval and execution boundaries

- **Pre-Judge only offers ALLOW or DEFER.** It does not produce a rejection or a BLOCK result. Ordinary approval and execution checks can still reject a call independently.
- **BYPASS skips structured Pre-Judge entirely, including shadow logging.** Both `icode run` and `icode workflow run` use BYPASS; `prejudge.yaml` does not change their approval behavior, and a BYPASS invocation does not validate the file.
- **Human-edited approvals are not re-evaluated.** When a person edits and approves a command, the new command is not evaluated again by Pre-Judge or LLM Judge. The edited command still goes through `before_tool_call` Hooks and the configured Shell Command Filter.
- **The Shell Command Filter checks the final command after approval and before the process starts.** BYPASS or human approval does not override it. However, this filter matches literal command names only and is **not a sandbox**: a blacklist of `[rm]` does not block every way to invoke `rm` (for example, `$'rm'`, `/bin/rm`, or `env rm`).
- **DEFER does not guarantee a human dialog.** Profile overrides, remembered authorization grants, and the AUTO LLM judge may still approve and execute the tool call.

**Policy lifetime:** Approval middleware sharing an EventBus uses one trusted policy snapshot. In the TUI, this lasts for the entire iCode process: `/new`, restoring a chat, or switching agents does not reload `prejudge.yaml`. Exit and restart iCode to apply edits. Main-agent, sub-agent, and workflow middleware use the same snapshot. If iCode begins in BYPASS, the snapshot is taken only after switching to MANUAL/AUTO.

If that first switch fails to load the policy, the requested MANUAL/AUTO mode still takes effect. The error is logged, and structured ALLOW and the read-only shortcut stay disabled for that EventBus lifetime; ordinary approval decides subsequent calls. Fix the configuration or parser installation and restart iCode to retry loading. Invalid enabled policies at ordinary startup still raise a path-qualified error.

**Shadow diagnostics:** At INFO level, Shadow logs the decision, reason, policy/rule IDs, matched spans, and a one-line representation of the command (truncated to 512 characters). Command text can include secrets; restrict access to these logs and avoid passing sensitive literal tokens.

### Compatibility and limitations

DEFER continues to the existing read-only checker and ordinary approval. For example, Zsh `ls` and PowerShell `Get-ChildItem` may still qualify for the read-only shortcut. The checker can approve commands containing globs even though the AST adapter cannot certify expanded argv. Moving the read-only checker into YAML is a separate design question. The `shell_filter: read_only` preset is an independent execution check. The policy author is responsible for the behavior of the trusted executables and arguments a rule authorizes.
