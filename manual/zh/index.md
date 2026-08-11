# Shodan Skill 用户指南

Shodan Skill 是一个非官方、以安全为先的命令行客户端和 Agent Skill，覆盖 Shodan 已公开文档中的 REST、Streaming、Trends 和 Exploits API。同一套 Python 实现为所有受支持的 Agent 平台提供一致的参数校验、传输、重试、超时、输出和脱敏行为。

本项目与 Shodan 不存在隶属、认可、赞助或官方合作关系。执行操作需要你自己的 Shodan 账户、API Key、积分以及相应服务权限。

## 从这里开始

- 按照[快速开始](getting-started/quickstart.md)安装程序并执行一个只读请求。
- 在执行扫描、告警、下载、数据流或 Enterprise 操作前，阅读[安全、积分与权限](concepts/safety.md)。
- 使用[命令速查](reference/commands.md)查看所有命令路径。
- 遇到认证、权限、超时或网络失败时，查看[故障排查](troubleshooting.md)。

## 项目覆盖范围

2.0.1 版本映射并通过契约测试覆盖了 2026-07-27 从 Shodan 公开开发者文档重新枚举的 58 个操作：45 个 REST、8 个 Streaming、3 个 Trends 和 2 个 Exploits 操作。CLI 还提供经过验证的数据集下载流程和本地参考命令。

官方公开的原始 HTTP API 是规范来源。仓库中的机器可读覆盖清单把每个已记录操作映射到一个 CLI 命令和一个模拟 HTTP 契约测试。官方 Python SDK 仅作为兼容性参考，不限制 HTTP API 的覆盖范围。

## 文档边界

本说明书解释用户工作流和项目特有行为。准确的响应字段应以链接的 Shodan 开发者文档和 Datapedia Schema 为准。要查看已安装版本支持的准确参数，请运行：

```bash
shodan-skill --help
shodan-skill GROUP ACTION --help
```

根目录 README 继续作为安装和项目概览入口。`SKILL.md` 与 `references/` 服务于 Agent 运行和机器校验，不作为另一套用户说明书。
