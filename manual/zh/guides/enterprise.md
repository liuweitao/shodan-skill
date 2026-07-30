# 企业数据与组织

这些工作流需要具有相应权限的 Enterprise 账户。无权限账户收到授权错误属于预期情况，不能报告为验证成功。

## 批量数据集

```bash
shodan-skill data list
shodan-skill data files raw-daily
shodan-skill data download raw-daily daily.json.gz --output-file daily.json.gz
```

下载流程先取得文件元数据，再把所选签名 HTTPS URL 的内容流式写入 `OUTPUT.part`。最终完成前，CLI 会校验预期大小和可用的 SHA-1 元数据。签名 URL 会被脱敏。

- `--resume` 使用有界 HTTP Range 请求继续已有部分文件。
- `--overwrite` 替换已有部分文件或最终文件。
- `--resume` 与 `--overwrite` 不能组合。
- `--no-verify` 明确关闭元数据 SHA-1 校验。
- `--chunk-size` 控制经过校验的本地流式分块大小。

未选择续传或覆盖时，已有文件会被保留，命令停止。如果下载期间其他进程创建了目标文件，最终完成会安全失败。可以使用根选项 `--dry-run` 预览目标行为。

## 组织成员

```bash
shodan-skill org info
shodan-skill org member add user@example.com --notify
shodan-skill org member remove user@example.com
```

成员变更会生成确定性预览。只有显式选择 `--notify` 或 `--no-notify` 时才转发通知参数；省略时保留服务默认值。移除成员属于破坏性操作。

Enterprise 互联网扫描另见[扫描指南](scans.md)。

官方 REST 参考：<https://developer.shodan.io/api>
