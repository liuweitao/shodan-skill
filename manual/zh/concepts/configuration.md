# 配置与超时

根选项必须写在命令组之前：

```bash
shodan-skill --read-timeout 45 --retries 1 host info 8.8.8.8
```

## 运行时设置

| 环境变量 | 根选项 | 默认值 | 约束 |
|---|---|---:|---|
| `SHODAN_CONNECT_TIMEOUT` | `--connect-timeout` | 10 秒 | 有限正数 |
| `SHODAN_READ_TIMEOUT` | `--read-timeout` | 30 秒 | 有限正数 |
| `SHODAN_WRITE_TIMEOUT` | `--write-timeout` | 30 秒 | 有限正数 |
| `SHODAN_POOL_TIMEOUT` | `--pool-timeout` | 10 秒 | 有限正数 |
| `SHODAN_STREAM_TIMEOUT` | `--stream-timeout` | 60 秒 | 有限正数 |
| `SHODAN_RETRIES` | `--retries` | 2 | 0 到 5 的整数 |
| `SHODAN_PROXY` | `--proxy` | 禁用 | 绝对 HTTP(S) URL |
| `SHODAN_SAFETY_MODE` | `--safety-mode` | `direct` | `direct` 或 `strict` |

显式根选项覆盖对应环境设置。无效值会在创建传输连接前于本地失败。

## 重试行为

不消耗积分的 GET 使用有界重试并遵守 `Retry-After`。消耗积分的 GET 不会自动重试，因为重试可能增加积分消耗。状态变更不会被静默重放。请求失败后，应先检查 stderr，再判断是否适合显式重试。

## 代理隔离

程序忽略 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 和 `.netrc`。代理 URL 含凭据时，优先使用 `SHODAN_PROXY`，因为进程参数可能出现在历史记录或进程列表中。代理凭据会从输出和错误中脱敏。

## 数据流超时

数据流超时是空闲或读取边界，并不代表会话可以无限运行。有限超时的数据流请求 `heartbeat=false`，避免心跳行掩盖空闲数据源。无人值守任务应设置明确的 `--limit` 和有界重连参数。
