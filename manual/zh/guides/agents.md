# Agent 平台

规范架构如下：

```text
自然语言请求
  -> 平台 Skill
  -> 已安装的 shodan-skill CLI
  -> 共享校验、安全、传输、输出和脱敏
  -> Shodan 服务
```

先安装 Python CLI，再把生成的 Skill Bundle 安装到平台发现目录：

```bash
python scripts/install_skill.py --platform codex
python scripts/install_skill.py --platform openclaw
python scripts/install_skill.py --platform claude-code
python scripts/install_skill.py --platform hermes
```

替换已有 Bundle 前，安装程序会请求确认。仅在确实需要替换时使用 `--yes`。平台 Bundle 由根目录 `SKILL.md` 和聚焦参考文件生成，不得手工修改生成副本。

## 请求行为

明确的自然语言操作请求会按照当前安全模式，与显式 CLI 命令同样处理。Agent 必须校验指定目标、保持请求范围，并调用已安装的 CLI。已配置密钥、可用积分或 Enterprise 权限不能授权未声明的操作。

示例：

```text
显示 8.8.8.8 当前的 Shodan 主机记录。
统计匹配 port:443 的主机数量，不执行完整主机搜索。
对我明确授权的目标预演一次 Shodan 扫描请求。
获取端口 22 和 443 的十条实时记录。
```

Agent Skill 使用渐进式参考处理搜索、扫描、Streaming、Enterprise、Schema 和安全规则。面向用户的连续教程属于本说明书，平台 Bundle 应保持简洁并专注于操作。
