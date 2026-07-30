# 任务配方

这些配方使用合成值或公开文档示例。实际使用前应审阅积分和授权要求。

## 检查主机并保留机器可读输出

```bash
shodan-skill host info 8.8.8.8
```

由于诊断保留在 stderr，JSON 信封可以单独重定向。主机记录仍可能包含敏感观察结果，应判断文件可以存放在哪里。

## 在获取匹配项前估算搜索

```bash
shodan-skill search count "product:nginx country:DE" --facets org:5
shodan-skill --dry-run search hosts "product:nginx country:DE" --facets org:5
shodan-skill search hosts "product:nginx country:DE" --facets org:5 --limit 20
```

计数不消耗查询积分。预演会校验并预览完整搜索。最后的本地数量限制只截断返回结果，不改变 API 分页语义。

## 检查剩余账户积分

```bash
shodan-skill account api-info
```

套餐及剩余查询或扫描积分应使用此命令。`account profile` 用途不同。

## 预览状态变更请求

```bash
shodan-skill --dry-run alert create "Example" 192.0.2.0/24 --expires 3600
```

预演会校验目标并显示确定性变更预览，但不会创建传输连接。

## 限制数据流

```bash
shodan-skill --stream-timeout 90 stream countries US,DE \
  --limit 25 --reconnect --max-reconnects 2
```

自动化任务应始终设置明确数量和超时。提前结束的结果应视为部分且失败的操作。

## 续传 Enterprise 下载

```bash
shodan-skill data download raw-daily daily.json.gz \
  --output-file daily.json.gz --resume
```

续传要求已有 `.part` 文件，并且服务端返回兼容的 Range 响应。除非显式选择 `--no-verify`，完整性校验保持开启。

## 向其他工具传递干净 JSON

使用默认 JSON 输出并保持 stderr 分离：

```bash
shodan-skill --output json search count "port:443"
```

解析前不要把 stderr 合并到 stdout，因为预览和诊断有意写入 stderr。
