# Structured Shell Pre-Judge

iCode can optionally inspect Bash, Git Bash, Zsh, and PowerShell commands using Tree-sitter and literal YAML rules before ordinary tool approval. It is **off by default** and returns only **ALLOW** or **DEFER**. ALLOW offers an automatic-approval shortcut. DEFER continues through existing approval. Pre-Judge itself does not deny commands. Ordinary approval and the independent Shell Command Filter can still reject a call.

Place `prejudge.yaml` in iCode's trusted user configuration directory (`~/.chrys/prejudge.yaml` on macOS/Linux). The user policy applies across profiles and workspaces using that configuration directory.

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

The AST matchers support static commands, supported pipelines, and independent commands in the dialects listed below. Unsupported shells such as `sh`, `dash`, `fish`, and `cmd.exe`, redirections, dynamic expansions, globs, and most control-flow constructs DEFER. Matching compares literal argv case-sensitively, including under PowerShell. Opaque wrappers such as `command`, `env`, and `time` also DEFER.

### Install the optional parser

Install the pinned packages into the Python 3.14 environment that runs iCode. The standard wheel and offline binary omit the optional parsers. Off mode works without them.

| Installation | Command |
| --- | --- |
| Source checkout | `uv sync --locked`, then `uv run icode` |
| uv tool | `uv tool install --reinstall --python 3.14 --with tree-sitter==0.25.1 --with tree-sitter-bash==0.25.1 --with tree-sitter-zsh==0.64.3 --with tree-sitter-pwsh==0.38.1 iCode-TUI` |
| pipx, after installing iCode-TUI | `pipx inject iCode-TUI "tree-sitter==0.25.1" "tree-sitter-bash==0.25.1" "tree-sitter-zsh==0.64.3" "tree-sitter-pwsh==0.38.1"` |

To verify the pins, run `python -c "from importlib.metadata import version; print([version(p) for p in ('tree-sitter', 'tree-sitter-bash', 'tree-sitter-zsh', 'tree-sitter-pwsh')])"` in that environment. In a source checkout use `uv run python`. For a uv tool installation, `uv tool dir` locates the `icode-tui` environment. For pipx use `pipx runpip iCode-TUI show tree-sitter tree-sitter-bash tree-sitter-zsh tree-sitter-pwsh`. For a wheel installation, install the parser pins into the same environment as the wheel. Use a managed Python installation when an offline binary has no supported way to install the parsers. An unavailable Zsh or PowerShell grammar causes that dialect to DEFER.

### Isolated launch

The configured shell runs the original approved text. iCode checks the original text and decoded arguments for sensitive targets. Every command in a supported pipeline or compound statement must match a rule.

| Shell | Isolation and supported command names |
| --- | --- |
| Bash / Git Bash | `--noprofile --norc`. The child environment drops `BASH_ENV`, `ENV`, and all `BASH_FUNC_*` entries. Bare names can qualify. |
| Zsh | `-f -d -o noaliases`. Bare names can qualify. The trusted system `zshenv` still runs and can control startup settings. |
| Windows PowerShell 5.1 and PowerShell 7+ | `-NoProfile -NonInteractive`. The Windows pipe backend adds its normal UTF-8 setup before encoding the script with `-EncodedCommand`. Approval stays bound to the original command. A resolvable native `.exe` or a supported module-qualified cmdlet can qualify. |

PowerShell examples include `git.exe status` and `Microsoft.PowerShell.Management\Get-ChildItem`. Qualified `Get-Item`, `Get-Content`, `Select-Object`, and `Write-Output` are also supported from their Microsoft modules. Unqualified cmdlets, aliases, `git status`, uncertain native argument quoting, and unresolved applications DEFER.

Provider paths such as `Variable:`, `HKCU:` and `Registry::` DEFER for supported PowerShell cmdlets. A native executable can receive literal colon arguments such as `HEAD:README.md` or an HTTPS URL. Decoded UNC and device paths DEFER in PowerShell and Git Bash, including paths supplied to native executables. These checks cover every command in a pipeline and Windows shell working directories. Ordinary drive-letter paths such as `C:\project\notes.txt` can still qualify. The path checks affect structured approval eligibility only. Ordinary approval, including the existing sensitive-target checks, continues to apply. On Windows, a PowerShell command whose encoded launch exceeds the process command-line limit DEFERs with `reason=launch_command_too_long`.

Ordinary approval and BYPASS retain their normal launch settings. Identical command text can behave differently when it relies on Bash functions, Zsh startup files that extend `PATH`, or PowerShell modules available in the normal session. The shortcut trusts system startup state, the inherited environment, `PATH`, `PSModulePath`, and the programs and modules they resolve. Relative search entries and recognized executable or module locations inside a known workspace DEFER. Keep trusted search directories and their contents outside locations the agent can change. Programs and modules outside those checks can change independently of the tool call. Opaque carriers such as `open`, `osascript`, and shell builtins that change execution state DEFER even if a broad rule matches.

PowerShell can add module locations at startup. Pre-Judge checks the Windows Documents module directory for the selected edition even when it is missing from the inherited `PSModulePath`. If the workspace includes that directory, or startup search paths cannot be verified, the call DEFERs. This includes a custom `powershell.config.json` that Pre-Judge cannot certify.

If any `PATH` directory is inside a workspace, Structured ALLOW is unavailable for commands using that launch context. This can happen with an activated project `.venv` or when iCode uses your home directory as its workspace. Look for `reason=untrusted_launch_context` in the diagnostics. These calls continue through ordinary approval, including the legacy read-only shortcut when applicable. A custom Shell argument list can also DEFER before execution (`reason=unsupported_shell_configuration`).

`cd` changes the directories used for command resolution and sensitive-target checks. A compound command such as `cd sub && git status` DEFERs for that reason. Zsh's `fc` also DEFERs because it can execute commands from shell history.

### Approval and execution boundaries

- **Pre-Judge only offers ALLOW or DEFER.** It does not produce a rejection or a BLOCK result. Ordinary approval and execution checks can still reject a call independently.
- **BYPASS skips structured Pre-Judge entirely, including shadow logging.** Both `icode run` and `icode workflow run` use BYPASS; `prejudge.yaml` does not change their approval behavior, and a BYPASS invocation does not validate the file.
- **Human-edited approvals are not re-evaluated.** When a person edits and approves a command, the new command is not evaluated again by Pre-Judge or LLM Judge. The edited command still goes through `before_tool_call` Hooks and the configured Shell Command Filter.
- **The Shell Command Filter checks the final command after approval and before the process starts.** BYPASS or human approval does not override it. However, this filter matches literal command names only and is **not a sandbox**: a blacklist of `[rm]` does not block every way to invoke `rm` (for example, `$'rm'`, `/bin/rm`, or `env rm`).
- **Approval order.** Mandatory sensitive-data checks take precedence. An eligible structured ALLOW or legacy read-only shortcut can satisfy a profile's `shell: require` before remembered authorization (DAA), the AUTO judge or manual approval. After DEFER, these existing paths can still approve the call. See [Configure approvals](./approval.md).

**Policy lifetime:** Approval middleware sharing an EventBus uses one trusted policy snapshot. In the TUI, this lasts for the entire iCode process: `/new`, restoring a chat, or switching agents does not reload `prejudge.yaml`. Exit and restart iCode to apply edits. Main-agent, sub-agent, and workflow middleware use the same snapshot. If iCode begins in BYPASS, the snapshot is taken only after switching to MANUAL/AUTO.

If that first switch fails to load the policy, the requested MANUAL/AUTO mode still takes effect. The TUI or ACP client receives a warning with the configuration path. Structured ALLOW stays disabled for this policy snapshot and ordinary approval, including the read-only shortcut, continues. Fix the YAML or parser installation and restart iCode to retry loading. Invalid enabled policies at ordinary startup raise a path-qualified error.

**Shadow diagnostics.** Shadow uses the same eligibility calculation as enforce mode and leaves approval unchanged. In the TUI, look for `shadow route=` in `logs/debug.log` under the iCode configuration directory. ACP keeps INFO off stderr. To observe ACP Shadow decisions, opt in with `CHRYS_OTEL=true` and leave the telemetry endpoint and sensitive-data collection unset. With local telemetry, look in the session's `otel/logs.jsonl`. INFO includes the decision, reason, policy/rule IDs and matched spans. DEBUG can include an escaped command preview of up to 512 characters. The headless CLI uses BYPASS.

The INFO field `policy_candidate` shows whether the AST and YAML rules qualify before sensitive-target and launch checks. The `route` field predicts the structured shortcut. When `decoded_sensitive_target=true`, the argument check found a target the raw text check missed. In enforce mode that finding can send a call to ordinary approval even if no YAML rule matches and the call previously ran automatically. It also prevents the existing read-only shortcut and remembered authorization from approving that call. Shadow reports the finding and preserves the current approval behavior.

### Compatibility and limitations

DEFER delegates to the existing read-only checker; it does not reimplement that checker as a second YAML engine. Its existing capabilities and limitations are retained, including shell-specific handling. This shortcut remains separate from the `shell_filter: read_only` preset, which has different semantics. The AST layer does not certify a glob as a fully resolved `argv_exact` vector, even when the legacy shortcut independently approves the command. Compatibility tests cover representative cases; they are not a proof of safety for every possible command.
