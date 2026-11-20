# Structured Shell Pre-Judge

iCode can optionally inspect Bash, Zsh, and PowerShell commands using Tree-sitter and literal YAML rules before ordinary tool approval. It is **off by default** and returns only **ALLOW** or **DEFER**. ALLOW offers an automatic-approval shortcut. DEFER continues through existing approval. Existing Hooks, approval policy, the read-only shortcut, remembered grants, and the **pre-execution** Shell Command Filter still apply.

Place `prejudge.yaml` in iCode's trusted user configuration directory (`~/.chrys/prejudge.yaml` on macOS/Linux). The policy applies across profiles and workspaces that use this directory.

```yaml
schema_version: 1
mode: "shadow"
policy_id: example-v1
rules:
  - id: allow-git-status
    effect: allow
    target: command
    match:
      argv_exact: ['/usr/bin/git', status]
```

### Matcher reference

Each rule uses `effect: allow`, `target: command`, and exactly **one** top-level matcher from this closed set of two literal matchers. DEFER is the default when a command cannot be allowed; it is not a configured rule effect. Regex, logical operators, CLI schemas, and other matcher names are not supported:

| Matcher | Meaning | Allowed effects |
| --- | --- | --- |
| `argv_exact: [git, status]` | Full literal argument vector equals exactly the given non-empty sequence | ALLOW |
| `argv_first: [echo]` | First token of the complete literal argument vector equals the given token | **ALLOW only** |

Matchers require **lists of non-empty literal strings**, even when there is only one token. `argv_first: [git]` matches every static Git subcommand, including mutating ones. The executable check still applies, and a broad rule such as `argv_first: ['/usr/bin/git']` can authorize mutating subcommands on eligible systems. Prefer `argv_exact` to limit the permitted arguments. Unknown keys, multiple matcher fields, empty lists, and non-string values are rejected during policy loading. Remove older rules that use `effect: block` or `prefix_first`. The policy schema version is `1`.

### Decision safety

A structured ALLOW requires complete source coverage, a fully decoded static argument vector and a matching rule for every executable AST node. In enforce mode, iCode also checks the raw command and decoded arguments for sensitive targets. A single certified command with a verified executable can use the shortcut. Anything unmatched, malformed, dynamic, or unsupported returns to existing approval, including its read-only shortcut.

Use `mode: "off"`, `mode: "shadow"`, or `mode: "enforce"`. Unquoted `mode: off` (parsed by YAML as `False`), `mode: false`, and an empty file also disable the feature without loading Tree-sitter. `shadow` logs proposed ALLOW/DEFER decisions without acting on them; `enforce` applies eligible ALLOW shortcuts. Malformed YAML **syntax** raises a path-qualified error at ordinary approval startup, even if the intended mode was `shadow`. Parseable `shadow` YAML with invalid rules or dependencies instead warns (with the file path and rule ID where applicable) and disables observation. Invalid `enforce` rules fail with the file path and rule ID. A BYPASS run does not load or validate `prejudge.yaml`; if approval mode later changes to MANUAL/AUTO, the policy is loaded then.

### Shells, syntax, and executable identity

| Shell | Tree-sitter grammar | Supported syntax |
| --- | --- | --- |
| Bash / Git Bash | `tree-sitter-bash==0.25.1` | Static Bash argv, supported quoting, pipelines, and supported compound commands. |
| Zsh | `tree-sitter-zsh==0.64.3` | Simple commands, bare arguments, single and double quoted literals, independent statements, and simple pipelines. |
| Windows PowerShell 5.1 (`powershell`) and PowerShell 7+ (`pwsh`) | `tree-sitter-pwsh==0.38.1` | Simple commands, literal arguments, separate parameter tokens such as `-LiteralPath`, independent statements, and simple pipelines. |

For Zsh and PowerShell, an ALLOW match requires a literal absolute executable path. The shared matcher compares literal tokens case-sensitively. Bare names, including PowerShell cmdlets such as `Get-Content`, may resolve to aliases, functions, or programs on PATH. An AST alone cannot establish that identity.

In enforce mode, automatic execution is currently available for Bash, Zsh, and PowerShell 7 on POSIX when a single command names a verified system binary in `/usr/bin` or `/bin`. Its path must be root-owned, free of symlinks and unwritable by the current process, group, or other users. iCode passes the certified arguments directly to the executable, so shell profiles, `zshenv`, aliases and functions do not participate. Pipelines, compound commands, bare Bash names, and Windows commands, including Git Bash and both PowerShell versions, continue through existing approval. Shadow can still show matching rules for these commands.

All adapters accept a conservative ASCII subset. Unsupported control characters, comments, line continuations, ambiguous escapes, dynamic expansion, redirections and parse errors DEFER. PowerShell accepts ordinary CRLF statement separators when the grammar covers the full source. Zsh defers glob qualifiers, option-dependent patterns and history expansion. PowerShell defers splatting, invocation operators, script blocks and native arguments whose quoting differs across versions. Unsupported shells such as `sh`, `dash`, `fish`, and `cmd.exe` continue through existing approval.

### Install the optional parsers

Install the parsers into the same Python 3.14 environment that runs iCode. An unavailable or incompatible additional grammar causes that dialect to DEFER. Off mode works without the parsers.

| Installation | Command |
| --- | --- |
| Source checkout | `uv sync --locked`, then `uv run icode` |
| uv tool | `uv tool install --reinstall --python 3.14 --with tree-sitter==0.25.1 --with tree-sitter-bash==0.25.1 --with tree-sitter-zsh==0.64.3 --with tree-sitter-pwsh==0.38.1 iCode-TUI` |
| pipx, after installing iCode-TUI | `pipx inject iCode-TUI "tree-sitter==0.25.1" "tree-sitter-bash==0.25.1" "tree-sitter-zsh==0.64.3" "tree-sitter-pwsh==0.38.1"` |

To check versions, run the following with the environment's Python. In a source checkout use `uv run python`. For a uv tool installation, `uv tool dir` locates the `icode-tui` environment. For pipx, use `pipx runpip iCode-TUI show tree-sitter tree-sitter-bash tree-sitter-zsh tree-sitter-pwsh`.

```sh
python -c "from importlib.metadata import version; print([version(p) for p in ('tree-sitter', 'tree-sitter-bash', 'tree-sitter-zsh', 'tree-sitter-pwsh')])"
```

The standard wheel and offline binary omit the optional parsers. When installing a wheel into a Python environment, install the same pins into that environment. Use a source, uv tool, or pipx installation for Pre-Judge if your offline binary has no supported way to install the optional wheels.

### Approval and execution boundaries

- **Pre-Judge only offers ALLOW or DEFER.** It does not produce a rejection or a BLOCK result. Ordinary approval and execution checks can still reject a call independently.
- **BYPASS skips structured Pre-Judge entirely, including shadow logging.** Both `icode run` and `icode workflow run` use BYPASS; `prejudge.yaml` does not change their approval behavior, and a BYPASS invocation does not validate the file.
- **Human-edited approvals are not re-evaluated.** When a person edits and approves a command, the new command is not evaluated again by Pre-Judge or LLM Judge. The edited command still goes through `before_tool_call` Hooks and the configured Shell Command Filter.
- **The Shell Command Filter checks the final command after approval and before the process starts.** BYPASS or human approval does not override it. However, this filter matches literal command names only and is **not a sandbox**: a blacklist of `[rm]` does not block every way to invoke `rm` (for example, `$'rm'`, `/bin/rm`, or `env rm`).
- **Approval order.** Mandatory sensitive-data review takes precedence over the shortcuts. Eligible Structured ALLOW and legacy read-only shortcuts can satisfy a profile's `shell: require` rule before remembered grants or the AUTO judge are consulted. After DEFER, profile rules, the read-only shortcut, remembered grants, or the AUTO judge may still approve the call. See [Configure approvals](./approval.md).

**Policy lifetime:** Approval middleware sharing an EventBus uses one trusted policy snapshot. In the TUI, this lasts for the entire iCode process: `/new`, restoring a chat, or switching agents does not reload `prejudge.yaml`. Exit and restart iCode to apply edits. Main-agent, sub-agent, and workflow middleware use the same snapshot. If iCode begins in BYPASS, the snapshot is taken only after switching to MANUAL/AUTO.

If that first switch fails to load the policy, the requested MANUAL/AUTO mode still takes effect. The TUI or ACP client receives a warning with the configuration path. Structured ALLOW stays disabled for that policy snapshot and ordinary approval, including the read-only shortcut, continues. Fix the YAML or parser installation and restart iCode to retry loading. Invalid enabled policies at ordinary startup still raise a path-qualified error.

**Shadow diagnostics.** In the TUI, look for `shadow route=` in `logs/debug.log` under the iCode configuration directory. ACP keeps INFO off stderr. To observe ACP Shadow decisions, opt in with `CHRYS_OTEL=true` and leave the telemetry endpoint and sensitive-data collection unset. With local telemetry, look in the session's `otel/logs.jsonl`. INFO records include the proposed rule decision, reason, policy/rule IDs and matched spans, with command text omitted. DEBUG can include an escaped command preview of up to 512 characters. Both headless CLI commands run in BYPASS and produce no Shadow decisions.

### Compatibility and limitations

DEFER continues to the existing read-only checker and ordinary approval. For example, Zsh `ls` and PowerShell `Get-ChildItem` may still qualify for the read-only shortcut. The checker can approve commands containing globs even though the AST adapter cannot certify expanded argv. Moving the read-only checker into YAML is a separate design question. The `shell_filter: read_only` preset is an independent execution check. The policy author is responsible for the behavior of the trusted executables and arguments a rule authorizes.
