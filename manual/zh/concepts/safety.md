# 安全、积分与权限

## Direct 模式

CLI 和 Agent Skill 默认使用 `direct`。明确输入命令或提出自然语言操作请求，即表示在本地校验后执行该操作。积分消耗、状态变更、下载、扫描、监控网络、数据流和 Enterprise 操作不会再次弹出确认。

定义了确定性预览的操作会把预览写入 stderr，然后继续执行。要在校验和预览后停止、且不创建传输连接，请把 `--dry-run` 放在命令组之前：

```bash
shodan-skill --dry-run scan submit 192.0.2.10
```

不得扩大目标列表或启动用户没有要求的操作。API Key 或账户权限只表示操作可以执行，并不代表用户要求执行。

## Strict 兼容模式

需要时显式选择严格模式：

```bash
shodan-skill --safety-mode strict scan submit 192.0.2.10 \
  --confirm --acknowledge-authorization
```

严格模式强制要求 `--confirm` 或 `--yes`。扫描和监控网络还要求 `--acknowledge-authorization`。这些选项必须完整书写，`--y`、`--conf` 和 `--ack` 等缩写会被拒绝。为兼容现有脚本，direct 模式仍接受这些选项。

## 积分影响

- 带过滤器的主机搜索和第一页之后的分页可能消耗查询积分。
- DNS 域名信息每次查询消耗一个查询积分。
- 按需扫描可能消耗扫描积分。
- 根据现有文档契约，`search count`、主机详情、元数据、账户和工具请求不消耗查询积分。
- 消耗积分的 GET 不会自动重试。

输出元数据包含 `credit_impact`；仅在请求前可以保守计算时填写 `credits_estimated`。兼容字段 `credits_used` 保持为 `null`，不能把它解释为零消耗。

## 权限与授权

互联网范围扫描、大多数全局或过滤数据流、Trends、数据集以及组织操作需要相应的 Enterprise 或服务权限。拥有告警的账户可能可以访问告警数据流。有效账户缺少所需权限时，出现授权错误 `4` 是预期行为。

只能扫描或监控你有权评估的目标。文档中的 `192.0.2.0/24` 等地址用于示例，不构成实际扫描指令。
