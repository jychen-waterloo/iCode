# 结构化 Shell Pre-Judge

iCode 可以使用 Tree-sitter 和字面量 YAML 规则分析 Bash、Zsh 和 PowerShell 指令，再进入原有工具审批。功能**默认关闭**，只返回 **ALLOW** 或 **DEFER**。ALLOW 提供快捷自动审批，DEFER 交给原有审批流程。原有 Hook、审批策略、只读快捷审批、已记住的授权和**执行前** Shell Command Filter 仍然适用。

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
      argv_exact: ['/usr/bin/git', status]
```

### 匹配规则

每条规则使用 `effect: allow` 和 `target: command`，`match` 只有一个顶层字段，且仅支持下列两种字面量匹配器。DEFER 是无法允许时的默认结果，不是可配置的规则效果。不支持正则表达式、逻辑运算、CLI 参数结构或其他匹配字段：

| 字段 | 匹配条件 | 允许效果 |
| --- | --- | --- |
| `argv_exact: [git, status]` | 完整静态参数列表与给定序列完全相等 | ALLOW |
| `argv_first: [echo]` | 完整静态参数列表的第一个 token 相等 | **仅 ALLOW** |

匹配器必须使用非空字符串**列表**，即使只有一个 token。`argv_first: [git]` 的 ALLOW 会匹配所有参数完整且静态的 Git 子命令，包括可能修改数据的操作；对含有高风险参数的命令优先使用 `argv_exact`。未知字段、多个匹配字段、空值和非字符串值都会在加载时被拒绝。已移除的 `effect: block` 和 `prefix_first` 会明确报错，而非被静默忽略；旧配置中的这些规则需要删除。策略格式版本仍为 `schema_version: 1`。

### 鉴权语义

结构化 ALLOW 要求覆盖完整的命令源码、解码出完整的静态参数，并为每个可执行 AST 节点匹配一条允许规则。在 enforce 模式下，iCode 还会检查原始命令和解码后的参数是否涉及敏感目标。只有经过验证的单条命令及其可执行文件才能使用快捷审批。未匹配、语法损坏、动态展开或不支持的构造会回到原有审批流程，包括只读快捷审批。

推荐使用 `mode: "off"`、`mode: "shadow"` 或 `mode: "enforce"`。未加引号的 `mode: off`（YAML 将其解析为布尔值 `False`）、`mode: false` 和空文件也会关闭功能，且不会加载 Tree-sitter。`shadow` 只记录建议的 ALLOW/DEFER，不执行快捷审批；`enforce` 执行符合条件的 ALLOW。**YAML 语法本身损坏**时，正常审批启动会报包含文件路径的错误，即使原本意图声明 `shadow`。可正常解析且明确声明 `shadow` 的配置，若规则或依赖无效，会记录含文件路径（和适用时规则 ID）的警告并停止观察；无效的 `enforce` 规则会报包含文件路径和规则 ID 的错误。BYPASS 不会加载或验证 `prejudge.yaml`；如果此会话随后切换到 MANUAL/AUTO，届时才加载配置。

### 支持的 Shell、语法与可执行文件身份

| Shell | Tree-sitter 文法 | 支持的语法 |
| --- | --- | --- |
| Bash / Git Bash | `tree-sitter-bash==0.25.1` | 静态 Bash 参数、已支持的引号、管道及复合命令。 |
| Zsh | `tree-sitter-zsh==0.64.3` | 简单命令、无引号参数、单引号与双引号字面量、独立语句及简单管道。 |
| Windows PowerShell 5.1（`powershell`）和 PowerShell 7+（`pwsh`） | `tree-sitter-pwsh==0.38.1` | 简单命令、字面量参数、独立的参数名（如 `-LiteralPath`）、独立语句及简单管道。 |

Zsh 和 PowerShell 的 ALLOW 规则匹配要求使用可执行文件的字面量绝对路径。共享匹配器比较字面参数并区分大小写。裸命令名可能解析为别名、函数或 PATH 上的程序，PowerShell 的 `Get-Content` 等 cmdlet 亦如此。AST 本身不足以确认实际执行对象。

在 enforce 模式下，Bash、Zsh 和 PowerShell 7 目前仅在 POSIX 上对单条命令使用结构化快捷审批。可执行文件必须是 `/usr/bin` 或 `/bin` 中经过验证的系统二进制。路径须由 root 所有、没有符号链接，且当前进程、所属组及其他用户均无法写入。iCode 将验证后的参数直接传给二进制，因此 Shell 配置文件、`zshenv`、别名和函数均不参与。管道、复合命令、Bash 裸命令名，以及 Windows 上的 Git Bash 和两个 PowerShell 版本都继续走原有审批。Shadow 仍可显示这些命令匹配的规则。

所有适配器均采用保守的 ASCII 子集。不支持的控制字符、注释、续行、含义不明确的转义、动态展开、重定向和解析错误均 DEFER。PowerShell 文法完整覆盖源码时，普通 CRLF 可用作语句分隔符。Zsh 对 glob 限定符、依赖选项的模式和历史展开返回 DEFER。PowerShell 对参数展开（splatting）、调用运算符、脚本块和存在跨版本引号差异的原生命令参数返回 DEFER。`sh`、`dash`、`fish` 和 `cmd.exe` 等未支持的 Shell 继续走原有审批。

### 安装可选解析器

请在运行 iCode 的同一 Python 3.14 环境中安装解析器。附加文法缺失或不兼容时，相应方言会 DEFER。Off 模式无需解析器。

| 安装方式 | 命令 |
| --- | --- |
| 源码检出 | `uv sync --locked`，然后运行 `uv run icode` |
| uv tool | `uv tool install --reinstall --python 3.14 --with tree-sitter==0.25.1 --with tree-sitter-bash==0.25.1 --with tree-sitter-zsh==0.64.3 --with tree-sitter-pwsh==0.38.1 iCode-TUI` |
| pipx（已安装 iCode-TUI） | `pipx inject iCode-TUI "tree-sitter==0.25.1" "tree-sitter-bash==0.25.1" "tree-sitter-zsh==0.64.3" "tree-sitter-pwsh==0.38.1"` |

使用该环境的 Python 运行以下命令查看版本。源码检出环境用 `uv run python`。uv tool 安装可通过 `uv tool dir` 找到 `icode-tui` 环境。pipx 安装可用 `pipx runpip iCode-TUI show tree-sitter tree-sitter-bash tree-sitter-zsh tree-sitter-pwsh`。

```sh
python -c "from importlib.metadata import version; print([version(p) for p in ('tree-sitter', 'tree-sitter-bash', 'tree-sitter-zsh', 'tree-sitter-pwsh')])"
```

标准 wheel 和离线二进制发行包不包含这些可选解析器。将 wheel 安装到 Python 环境时，请在同一环境中安装上述固定版本。如果离线包不支持安装可选 wheel，请改用源码、uv tool 或 pipx 安装来启用 Pre-Judge。

### 审批及执行边界

- **Pre-Judge 只返回 ALLOW 或 DEFER。** 本层不产生拒绝或 BLOCK 结果；正常审批和执行检查仍可独立拒绝调用。
- **BYPASS 完全跳过 Structured Pre-Judge，包括 shadow 日志。** `icode run` 与 `icode workflow run` 都使用 BYPASS，`prejudge.yaml` 不改变其审批行为；BYPASS 也不验证这份配置。
- **用户编辑并批准后的命令不会重新鉴权。** 编辑后的命令不会再次经过 Pre-Judge 或 LLM Judge，但仍须经过 `before_tool_call` Hook 和已配置的 Shell Command Filter。
- **Shell Command Filter 在审批之后、实际进程启动之前检查最终命令。** BYPASS 或人工批准都不能覆盖这项检查。过滤器匹配可识别的字面量命令名。
- **审批顺序。** 必须进行的敏感数据审批优先于快捷审批。符合条件的结构化 ALLOW 和原有只读快捷审批可以先于授权复用和 AUTO 审批裁判满足 Profile 的 `shell: require`。DEFER 后，Profile 规则、只读快捷审批、已有授权或 AUTO 审批裁判仍可能批准调用。参见[配置审批](./approval.md)。

**策略生命周期：** 使用同一 EventBus 的审批中间件共享一份可信策略快照。在 TUI 中，这份快照持续到 iCode 进程退出；`/new`、恢复聊天和切换 Agent 都不会重新加载 `prejudge.yaml`，需要退出并重启 iCode 才能应用修改。主 Agent、Sub-Agent 和 Workflow 使用同一快照。若 iCode 以 BYPASS 开始，在首次切换到 MANUAL/AUTO 时才加载快照。

如果首次切换时策略加载失败，所选的 MANUAL/AUTO 模式仍然生效。TUI 或 ACP 客户端会收到含配置路径的警告。此策略快照停用结构化 ALLOW，原有审批流程及其只读快捷审批继续工作。修复 YAML 或解析器安装后，重启 iCode 即可重试加载。正常启动时，无效的已启用策略仍会抛出包含路径的错误。

**Shadow 日志。** TUI 用户可在 iCode 配置目录的 `logs/debug.log` 中搜索 `shadow route=`。ACP 的 stderr 不输出 INFO。需要查看 ACP 的 Shadow 判定时，可设置 `CHRYS_OTEL=true`，同时保持遥测端点和敏感数据采集未配置，然后查看会话的 `otel/logs.jsonl`。INFO 记录包含建议判定、原因、策略及规则 ID 和匹配范围，省略命令文本。DEBUG 可能包含最多 512 字符的转义命令预览。两个无界面 CLI 命令均使用 BYPASS，因此没有 Shadow 判定。

### 兼容性与当前限制

DEFER 继续走现有只读检查器和正常审批。例如，Zsh 的 `ls` 和 PowerShell 的 `Get-ChildItem` 仍可能通过只读快捷审批。该检查器可能允许带 glob 的命令，即使 AST 适配器无法验证展开后的参数。将只读检查器迁移到 YAML 是独立的设计问题。`shell_filter: read_only` 预设是独立的执行检查。规则作者应确认所授权的可执行文件和参数的行为。
