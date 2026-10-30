# 结构化 Shell Pre-Judge

iCode 可选地使用 Bash 语法解析器和 CEL 策略分析命令，再进入工具审批。**默认关闭**。原有审批规则、Hook、授权复用以及后置 Shell Command Filter 不会被替换。

请在用户级配置目录放置 `prejudge.yaml`（macOS/Linux 通常为 `~/.chrys/`，Windows 使用 iCode 用户配置目录）。不会从工作区加载策略。

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

配置中的 `mode` 必须带引号，否则 YAML 可能将 `off` 解释为布尔值。`off` 保持原行为；`shadow` 只记录新决策，不影响执行；`enforce` 阻止确定匹配的 BLOCK，只在原有强制检查允许时快捷批准完全覆盖的 ALLOW，其他情况进入常规审批。显式 BYPASS 模式保持原有语义。

当前只支持 Bash / Git Bash；不把 zsh、sh、dash、PowerShell 或 cmd.exe 误认为 Bash。未知方言或不支持的语法不能被新模块自动 ALLOW；在 enforce 下通常仍需人工或 Judge 审批，可能增加弹窗。变量展开、重定向、通配符和大多数控制流结构不能自动批准；其中确定的静态命令节点仍可能命中 BLOCK。该功能不能代替完整 Shell 安全边界。

启用时需要额外安装 `tree-sitter==0.25.1`、`tree-sitter-bash==0.25.1` 和 `cel-expr-python==0.1.3`。CEL 的 Linux wheel 不兼容目前离线发行版本的 glibc 2.17 最低要求。无效配置或缺少 CEL 后端会报配置错误，不会静默关闭安全策略；解析器运行失败则交由常规审批处理。发行兼容和完整集成测试仍待验收。
