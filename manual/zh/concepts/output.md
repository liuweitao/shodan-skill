# 输出、错误与脱敏

## 稳定信封

非流式 stdout 默认输出稳定 JSON 信封：

```json
{
  "ok": true,
  "data": {},
  "meta": {
    "command": "host-info",
    "credits_used": null,
    "credit_impact": "none",
    "credits_estimated": null
  },
  "error": null
}
```

在命令组之前选择 `--output json`、`--output jsonl` 或 `--output human`。结构化成功结果写入 stdout；诊断、状态变更预览、重连事件和调试事件写入 stderr。

数据流默认每行输出一个信封。使用 `--stream-format sse` 时，每个信封作为 SSE `data:` 事件输出，并以空行结束。

## 退出码

| 退出码 | 含义 |
|---:|---|
| 0 | 成功 |
| 2 | 用法错误或严格模式安全门禁 |
| 3 | 认证失败 |
| 4 | 授权或权限不足 |
| 5 | 积分错误 |
| 6 | 网络错误 |
| 7 | API、下载或完整性错误 |
| 8 | 超时 |
| 9 | 数据流或操作被中断 |
| 10 | 未预期的内部错误 |

脚本应先检查退出码，再处理结果。数据流在达到请求数量前结束时会返回网络错误，不会把部分输出报告为完整成功。

## 递归脱敏

CLI 会从结构化输出和错误中脱敏 API Key、凭据类字段、Bearer Token、Authorization Header、Cookie、通知器参数、Routing Key、Webhook URL、签名下载 URL 和代理凭据。Shodan API Key 在内部作为查询认证传递，但不会显示在 URL 中。

脱敏只能降低意外泄露风险，不代表任意输出都适合公开。即使移除了凭据，主机数据、账户信息、告警、请求头和组织成员信息仍可能敏感。
