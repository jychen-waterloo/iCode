# 结构化 Pre-Judge（PR1 实验实现）

新路由与旧 readonly/regex Pre-Judge、DAA、LLM Judge 和后置
ShellCommandFilter 独立。默认 off。策略只从用户配置目录的
prejudge.yaml 加载，不读取工作区配置。

off 保持旧路由；shadow 只观察；enforce 对确定的 BLOCK 拒绝，
对确定 ALLOW 在敏感目标保护允许时快捷放行，其余走旧审批路径，
且 DEFER 不再执行旧 readonly 快捷批准。

可选依赖是 tree-sitter==0.25.1、tree-sitter-bash==0.25.1、
cel-expr-python==0.1.3。官方 CEL Linux wheel 的 glibc 需求
高于离线发行目标 2.17，发行矩阵未验证前不能改成强制依赖。

本分支还没有完成 CEL 编译类型验证、完整 corpus、人工确认后
Hook 改写重审、回归与发行测试，不能标记为正式完成。
