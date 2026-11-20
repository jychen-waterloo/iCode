# 结构化 Shell Pre-Judge

iCode 可以使用 Tree-sitter 和字面量 YAML 规则分析 Bash、Zsh 和 PowerShell 指令，再进入原有工具审批。功能**默认关闭**，只返回 **ALLOW** 或 **DEFER**。ALLOW 提供快捷自动审批，DEFER 交给原有审批流程。原有 Hook、审批策略、只读快捷审批、已记住的授权和**执行前** Shell Command Filter 仍然适用。

将配置存放在受信任的用户级目录中（macOS/Linux 通常为 `~/.chrys/prejudge.yaml`），不会从项目工作目录加载策略。

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

### 支持的 Shell、语法与可执行文件身份

| Shell | Tree-sitter 文法 | 支持的语法 |
| --- | --- | --- |
| Bash / Git Bash | `tree-sitter-bash==0.25.1` | 静态 Bash 参数、引号、管道及已支持的复合命令。现有 Bash 规则行为保留。 |
| Zsh | `tree-sitter-zsh==0.64.3` | 简单命令、无引号参数、单引号与双引号字面量、独立语句及简单管道。 |
| Windows PowerShell 5.1（`powershell`）和 PowerShell 7+（`pwsh`） | `tree-sitter-pwsh==0.38.1` | 简单命令、字面量参数、独立的参数名（如 `-LiteralPath`）、独立语句及简单管道。 |

Zsh 和 PowerShell 的每条命令还须以**受信任可执行文件的字面量绝对路径**开头，才能由匹配规则 ALLOW。在 Windows PowerShell 和 Windows `pwsh` 中，使用带盘符的 `.exe` 路径。例如，Zsh 可用 `argv_exact: ['/usr/bin/git', status]`，Windows 可用 `argv_exact: ['C:/Windows/System32/whoami.exe', /user]`。规则按原始路径拼写匹配并区分大小写，即使 Shell 本身不区分大小写。请选择自己控制或信任的路径。

Zsh 的 `git status` 和 PowerShell 的 `Get-Content -LiteralPath README.md` 可以提取静态参数，但由于尚未确认可执行文件或 cmdlet 的身份，会返回 DEFER。裸命令名可能解析为别名、函数、cmdlet 或 PATH 上的程序。这两种方言通过结构化 ALLOW 时，Shell 会跳过用户启动文件或配置文件。Zsh 仍会读取系统 `zshenv`，此检查依赖受信任的 Shell 安装与遵守启动选项的系统配置。

Zsh 和 PowerShell 适配器只接受经过验证的 ASCII 字面量子集。动态展开、Zsh glob 限定符、依赖选项的模式与历史展开、PowerShell 参数展开（splatting）、调用运算符与脚本块、重定向和解析错误均 DEFER。Windows 原生命令在不同 PowerShell 版本间存在引号处理差异，相关参数也会 DEFER。`sh`、`dash`、`fish` 和 `cmd.exe` 等未支持的 Shell 继续走原审批流程。

**依赖：**启用 Pre-Judge 时，在运行 iCode 的 Python 环境安装 `tree-sitter==0.25.1` 和固定版本的 Bash 文法。使用 Zsh 或 PowerShell 适配器时，再安装相应文法。附加文法缺失或不兼容时，该方言会 DEFER。可选文法提供兼容 Python 3.14 的 Linux、macOS 和 Windows wheel。标准 wheel 和离线发行包不包含这些可选依赖。开发环境通过 `uv sync` 安装，`off` 模式不会加载它们。

### 审批及执行边界

- **Pre-Judge 只返回 ALLOW 或 DEFER。** 本层不产生拒绝或 BLOCK 结果；正常审批和执行检查仍可独立拒绝调用。
- **BYPASS 完全跳过 Structured Pre-Judge，包括 shadow 日志。** `icode run` 与 `icode workflow run` 都使用 BYPASS，`prejudge.yaml` 不改变其审批行为；BYPASS 也不验证这份配置。
- **用户编辑并批准后的命令不会重新鉴权。** 编辑后的命令不会再次经过 Pre-Judge 或 LLM Judge，但仍须经过 `before_tool_call` Hook 和已配置的 Shell Command Filter。
- **Shell Command Filter 在人工审批之后、实际进程启动之前检查最终命令。** BYPASS 或人工批准都不能覆盖这项检查。但该过滤器仅匹配可识别的字面量命令名，**不是沙箱**：黑名单 `[rm]` 不能拦截所有 `rm` 调用方式，例如 `$'rm'`、`/bin/rm`、`env rm`。
- **DEFER 不保证弹出人工审批窗口。** Profile override、已有授权复用及 AUTO 模式的 LLM Judge 仍可能批准命令并执行。

**策略生命周期：** 使用同一 EventBus 的审批中间件共享一份可信策略快照。在 TUI 中，这份快照持续到 iCode 进程退出；`/new`、恢复聊天和切换 Agent 都不会重新加载 `prejudge.yaml`，需要退出并重启 iCode 才能应用修改。主 Agent、Sub-Agent 和 Workflow 使用同一快照。若 iCode 以 BYPASS 开始，在首次切换到 MANUAL/AUTO 时才加载快照。

如果首次切换时策略加载失败，所选的 MANUAL/AUTO 模式仍然生效。系统记录错误，并在该 EventBus 生命周期内停用结构化 ALLOW 和只读快捷审批，由原有审批流程决定后续调用。修复配置或解析器安装后，需要重启 iCode 才能重试加载。正常启动时，无效的已启用策略仍会抛出包含路径的错误。

**Shadow 日志：** INFO 日志包括判定、原因、Policy/Rule ID、匹配 span，以及转义换行、最多 512 个字符的命令文本。命令可能含有敏感 Token；应限制日志访问，并避免在命令中放入明文凭据。

### 兼容性与当前限制

DEFER 继续走现有只读检查器和正常审批。例如，Zsh 的 `ls` 和 PowerShell 的 `Get-ChildItem` 仍可能通过只读快捷审批。该检查器可能允许带 glob 的命令，即使 AST 适配器无法验证展开后的参数。将只读检查器迁移到 YAML 是独立的设计问题。`shell_filter: read_only` 预设是独立的执行检查。规则作者应确认所授权的可执行文件和参数的行为。
