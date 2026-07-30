# 告警与通知器

告警会监控明确提供的网络。创建或编辑告警不等于获得监控授权；应确认有权监控每一个目标。

## 读取告警状态

```bash
shodan-skill alert list --include-expired
shodan-skill alert info ALERT_ID --no-include-expired
shodan-skill alert triggers
```

省略 include-expired 选项时保留服务默认行为。

## 管理告警

```bash
shodan-skill alert create "Production" 192.0.2.0/24 --expires 0
shodan-skill alert edit ALERT_ID 192.0.2.0/24
shodan-skill alert delete ALERT_ID
shodan-skill alert trigger enable ALERT_ID new_service
shodan-skill alert trigger disable ALERT_ID new_service
shodan-skill alert trigger ignore ALERT_ID new_service 192.0.2.10:443
shodan-skill alert trigger unignore ALERT_ID new_service 192.0.2.10:443
```

创建、编辑、删除、触发器、忽略和通知器关联命令都会生成确定性预览。使用根选项 `--dry-run` 可在校验后停止。

## 管理通知器

```bash
shodan-skill notifier list
shodan-skill notifier info NOTIFIER_ID
shodan-skill notifier providers
shodan-skill notifier create slack --arg webhook_url=https://example.invalid/synthetic --description "Synthetic example"
shodan-skill notifier edit NOTIFIER_ID --arg key=synthetic-value
shodan-skill notifier delete NOTIFIER_ID
shodan-skill alert notifier add ALERT_ID NOTIFIER_ID
shodan-skill alert notifier remove ALERT_ID NOTIFIER_ID
```

创建通知器时必须提供说明。多个提供商参数可重复使用 `--arg NAME=VALUE`。参数经常包含 Routing Key、Webhook URL 或 Token；应尽可能避免进入命令历史，也不得在文档或 Issue 中使用真实秘密信息。

CLI 会递归脱敏通知器秘密信息和告警响应，但预览仍会标明请求对象和操作。删除告警或通知器以及移除关联属于破坏性或状态变更操作。

官方 REST 参考：<https://developer.shodan.io/api>
