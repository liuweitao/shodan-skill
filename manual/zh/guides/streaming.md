# 实时数据流

Streaming 请求使用 `https://stream.shodan.io`。告警数据流要求账户拥有告警；全局 Banner、ASN、国家、端口、漏洞和自定义查询数据流需要相应的 Streaming 或 Enterprise 权限。

## 数据流命令

```bash
shodan-skill stream banners --limit 10
shodan-skill stream asn AS123,AS456 --limit 10
shodan-skill stream countries US,DE --limit 10
shodan-skill stream ports 22,443 --limit 10
shodan-skill stream vulns CVE-2024-1234 --limit 10
shodan-skill stream alerts --limit 10
shodan-skill stream alert ALERT_ID --limit 10
shodan-skill stream custom "product:nginx" --limit 10
```

选择器会在连接前校验。ASN 输入接受 `AS123` 或 `123`，发送时使用数字路径形式。自定义查询会保留过滤器名称的大小写。

## 输出格式

默认使用 JSON Lines。请求并输出 SSE：

```bash
shodan-skill stream ports 22,443 --limit 10 --stream-format sse
```

每条非调试记录都使用稳定输出信封。服务端调试或丢弃事件以及重连诊断写入 stderr，不计入数量限制。`--debug` 会发送文档中的 `debug=1` 请求参数。

## 数量、超时和重连

默认数量是 10，避免无人值守命令无限运行。有限数据流超时和 `heartbeat=false` 可以防止心跳行掩盖空闲数据源。需要继续连接时，应明确启用有界重连：

```bash
shodan-skill --stream-timeout 90 stream ports 22,443 \
  --limit 100 --reconnect --max-reconnects 3
```

最大可接受重连次数为 10。在达到请求记录数前发生断线、超时或正常 EOF 都属于网络错误。Ctrl+C 返回操作中断退出码 `9`。

官方 Streaming 参考：<https://developer.shodan.io/api/stream>
