# 结构化 Shell Pre-Judge

iCode 可以使用 Tree-sitter 和字面量 YAML 规则分析 Bash、Git Bash、Zsh 和 PowerShell 指令，再进入原有工具审批。功能**默认关闭**，只返回 **ALLOW** 或 **DEFER**。ALLOW 提供快捷自动审批，DEFER 交给原有审批流程。原有 Hook、审批策略、只读快捷审批、DAA（已有授权复用机制）、已记住的授权和**执行前** Shell Command Filter 的行为均保留。

将配置存放在受信任的用户级目录中（macOS/Linux 通常为 `~/.chrys/prejudge.yaml`）。使用该配置目录的所有 Profile 和工作区共享此策略。

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

### 匹配规则

每条规则使用 `effect: allow` 和 `target: command`，`match` 只有一个顶层字段，且仅支持下列两种字面量匹配器。DEFER 是无法允许时的默认结果，不是可配置的规则效果。不支持正则表达式、逻辑运算、CLI 参数结构或其他匹配字段：

| 字段 | 匹配条件 | 允许效果 |
| --- | --- | --- |
| `argv_exact: [git, status]` | 完整静态参数列表与给定序列完全相等 | ALLOW |
| `argv_first: [echo]` | 完整静态参数列表的第一个 token 相等 | **仅 ALLOW** |

匹配器必须使用非空字符串**列表**，即使只有一个 token。`argv_first: [git]` 的 ALLOW 会匹配所有参数完整且静态的 Git 子命令，包括可能修改数据的操作；对含有高风险参数的命令优先使用 `argv_exact`。未知字段、多个匹配字段、空值和非字符串值都会在加载时被拒绝。已移除的 `effect: block` 和 `prefix_first` 会明确报错，而非被静默忽略；旧配置中的这些规则需要删除。策略格式版本仍为 `schema_version: 1`。

### 鉴权语义

要由结构化规则 ALLOW，必须所有可执行 AST 节点匹配 ALLOW、命令 `argv` 完整且语法覆盖完整。未匹配、语法损坏、动态展开或不支持的构造均返回 DEFER，继续进入原有审批流程，包括只读快捷审批和敏感数据检查。例如，没有 ALLOW 规则匹配的 `rm x` 会进入正常审批，而不会被 Pre-Judge 拒绝。`ls *.py`、`ls 2>/dev/null`、`sort f` 等原有只读审批仍然有效，配置 `rules: []` 时也是如此。静态前缀不能用于证明 ALLOW；`echo "rm"` 中的 `rm` 是参数，不是另一个可执行命令。

推荐使用 `mode: "off"`、`mode: "shadow"` 或 `mode: "enforce"`。未加引号的 `mode: off`（YAML 将其解析为布尔值 `False`）、`mode: false` 和空文件也会关闭功能，且不会加载 Tree-sitter。`shadow` 只记录建议的 ALLOW/DEFER，不执行快捷审批；`enforce` 执行符合条件的 ALLOW。**YAML 语法本身损坏**时，正常审批启动会报包含文件路径的错误，即使原本意图声明 `shadow`。可正常解析且明确声明 `shadow` 的配置，若规则或依赖无效，会记录含文件路径（和适用时规则 ID）的警告并停止观察；无效的 `enforce` 规则会报包含文件路径和规则 ID 的错误。BYPASS 不会加载或验证 `prejudge.yaml`；如果此会话随后切换到 MANUAL/AUTO，届时才加载配置。

AST Matcher 支持下表所列 Shell 的静态命令、受支持的管道和独立语句。`sh`、`dash`、`fish` 和 `cmd.exe` 等不支持的 Shell，以及重定向、动态展开、通配符和多数控制流构造均 DEFER。包括 PowerShell 在内，规则始终按字面参数区分大小写。`command`、`env` 和 `time` 等包装命令也会 DEFER。

### 安装可选解析器

请在运行 iCode 的同一 Python 3.14 环境中安装固定版本。标准 wheel 和离线二进制发行包不包含可选解析器。Off 模式无需解析器。

| 安装方式 | 命令 |
| --- | --- |
| 源码检出 | `uv sync --locked`，然后运行 `uv run icode` |
| uv tool | `uv tool install --reinstall --python 3.14 --with tree-sitter==0.25.1 --with tree-sitter-bash==0.25.1 --with tree-sitter-zsh==0.64.3 --with tree-sitter-pwsh==0.38.1 iCode-TUI` |
| pipx（已安装 iCode-TUI） | `pipx inject iCode-TUI "tree-sitter==0.25.1" "tree-sitter-bash==0.25.1" "tree-sitter-zsh==0.64.3" "tree-sitter-pwsh==0.38.1"` |

在相应环境中运行 `python -c "from importlib.metadata import version; print([version(p) for p in ('tree-sitter', 'tree-sitter-bash', 'tree-sitter-zsh', 'tree-sitter-pwsh')])"` 查看版本。源码检出环境使用 `uv run python`。uv tool 安装可通过 `uv tool dir` 找到 `icode-tui` 环境。pipx 安装可用 `pipx runpip iCode-TUI show tree-sitter tree-sitter-bash tree-sitter-zsh tree-sitter-pwsh`。将 wheel 安装到 Python 环境时，请在同一环境中安装解析器。如果离线包不支持安装解析器，请改用可管理的 Python 环境安装。缺少可用的 Zsh 或 PowerShell 文法时，相应方言会 DEFER。

### 隔离启动

配置的 Shell 执行获批的原始文本。iCode 同时检查原始文本和解码参数是否涉及敏感目标。受支持的管道或复合语句中，每条命令都必须匹配规则。

| Shell | 隔离方式与支持的命令名 |
| --- | --- |
| Bash / Git Bash | `--noprofile --norc`。子进程环境移除 `BASH_ENV`、`ENV` 和全部 `BASH_FUNC_*` 项。裸命令名可以匹配。 |
| Zsh | `-f -d -o noaliases`。裸命令名可以匹配。可信的系统级 `zshenv` 仍会运行，且可控制启动设置。 |
| Windows PowerShell 5.1 与 PowerShell 7+ | `-NoProfile -NonInteractive`。通过 `-EncodedCommand` 传递原始文本。可解析到的原生 `.exe` 或受支持的模块限定 cmdlet 可以匹配。 |

PowerShell 示例包括 `git.exe status` 和 `Microsoft.PowerShell.Management\Get-ChildItem`。也支持相应 Microsoft 模块中的 `Get-Item`、`Get-Content`、`Select-Object` 和 `Write-Output` 全限定名。未限定的 cmdlet、别名和 `git status` 均 DEFER。访问 Environment Provider、原生命令引号含义不明确或找不到可执行文件时同样 DEFER。

普通审批和 BYPASS 保留原有启动设置。依赖继承的 Bash 函数、通过 Zsh 启动文件加入的 `PATH` 项，或普通 PowerShell 会话中可用模块的命令，使用结构化快捷审批时可能表现不同。该快捷审批信任系统启动状态、继承的环境、`PATH`、`PSModulePath` 和通过它们解析到的程序及模块。使用相对查找路径或落在已知工作区内的可执行文件或模块目录时会 DEFER。请将可信程序、模块和搜索目录放在 Agent 无法修改的位置。检查范围之外的程序和模块可以独立于工具调用发生变化。即使匹配宽泛规则，`open`、`osascript` 和更改执行状态的 Shell 内建命令也会 DEFER。

### 审批及执行边界

- **Pre-Judge 只返回 ALLOW 或 DEFER。** 本层不产生拒绝或 BLOCK 结果；正常审批和执行检查仍可独立拒绝调用。
- **BYPASS 完全跳过 Structured Pre-Judge，包括 shadow 日志。** `icode run` 与 `icode workflow run` 都使用 BYPASS，`prejudge.yaml` 不改变其审批行为；BYPASS 也不验证这份配置。
- **用户编辑并批准后的命令不会重新鉴权。** 编辑后的命令不会再次经过 Pre-Judge 或 LLM Judge，但仍须经过 `before_tool_call` Hook 和已配置的 Shell Command Filter。
- **Shell Command Filter 在审批之后、实际进程启动之前检查最终命令。** BYPASS 或人工批准都不能覆盖这项检查。过滤器匹配可识别的字面量命令名。
- **审批顺序。** 必须进行的敏感数据检查优先。符合条件的结构化 ALLOW 或原有只读快捷审批可以先于已有授权复用（DAA）、AUTO 审批裁判或人工审批满足 Profile 的 `shell: require`。DEFER 后，原有审批路径仍可能批准调用。参见[配置审批](./approval.md)。

**策略生命周期：** 使用同一 EventBus 的审批中间件共享一份可信策略快照。在 TUI 中，这份快照持续到 iCode 进程退出；`/new`、恢复聊天和切换 Agent 都不会重新加载 `prejudge.yaml`，需要退出并重启 iCode 才能应用修改。主 Agent、Sub-Agent 和 Workflow 使用同一快照。若 iCode 以 BYPASS 开始，在首次切换到 MANUAL/AUTO 时才加载快照。

如果首次切换时策略加载失败，所选的 MANUAL/AUTO 模式仍然生效。TUI 或 ACP 客户端会收到含配置路径的警告。此策略快照停用结构化 ALLOW，原有审批流程及其只读快捷审批继续工作。修复 YAML 或解析器安装后，重启 iCode 即可重试加载。正常启动时，无效的已启用策略会抛出包含路径的错误。

**Shadow 日志。** Shadow 和 enforce 使用相同的资格判断，审批结果保持不变。TUI 用户可在 iCode 配置目录的 `logs/debug.log` 中搜索 `shadow route=`。ACP 的 stderr 不输出 INFO。需要查看 ACP 的 Shadow 判定时，可设置 `CHRYS_OTEL=true`，同时保持遥测端点和敏感数据采集未配置，然后查看会话的 `otel/logs.jsonl`。INFO 记录包含判定、原因、策略及规则 ID 和匹配范围。DEBUG 可能包含最多 512 字符的转义命令预览。无界面 CLI 使用 BYPASS。

### 兼容性与当前限制

DEFER 直接复用既有只读检查器，而不再用另一套 YAML 引擎重写它。原有能力和限制均保留，包括各 Shell 的处理方式。这条快捷审批与 `shell_filter: read_only` 预设相互独立，两者语义不同。即使原有快捷审批允许某条命令，AST 层也不会把未展开的 glob 认定为完整的静态 `argv_exact` 参数。兼容性测试覆盖了代表性案例，并不证明所有可能命令都安全。
