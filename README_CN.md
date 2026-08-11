# Shodan Skill

[![PyPI 版本](https://img.shields.io/pypi/v/shodan-skill.svg)](https://pypi.org/project/shodan-skill/)
[![Python 版本](https://img.shields.io/pypi/pyversions/shodan-skill.svg)](https://pypi.org/project/shodan-skill/)
[![CI](https://github.com/liuweitao/shodan-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/liuweitao/shodan-skill/actions/workflows/ci.yml)
[![文档](https://github.com/liuweitao/shodan-skill/actions/workflows/docs.yml/badge.svg)](https://github.com/liuweitao/shodan-skill/actions/workflows/docs.yml)

一个非官方、以安全为先的 Shodan 命令行客户端及通用 Agent Skill。OpenClaw、Codex、Claude Code 与 Hermes 共用同一个可移植的 `shodan-skill` 实现。

本项目与 Shodan 不存在隶属、认可、赞助或官方合作关系；Shodan 名称及服务引用仅用于说明 API 兼容性。

[English](README.md) | [中文](README_CN.md)

[完整英文说明书](https://liuweitao.github.io/shodan-skill/) | [完整中文说明书](https://liuweitao.github.io/shodan-skill/zh/)

双语说明书提供按任务组织的指南、命令速查、操作配方和故障排查。本 README 继续作为简洁的项目及安装入口。

## 安装并执行只读查询

需要 Python 3.10 或更高版本。从 PyPI 安装 CLI：

```bash
python -m pip install shodan-skill
shodan-skill --version
```

配置 `SHODAN_API_KEY` 或 Shodan 官方 CLI 密钥文件后，可以执行只读主机查询：

```bash
shodan-skill host info 8.8.8.8
```

Agent Skill 与平台 Bundle 仍独立于 Python 包安装，具体入口见[文档漂移、平台与测试](#文档漂移平台与测试)。

## 已验证范围

2.0.1 版依据 2026-07-27 的官方开发者文档重新枚举并通过离线契约测试覆盖全部 58 个操作：45 个 REST、8 个 Streaming、3 个 Trends 和 2 个 Exploits 操作。它们覆盖主机、搜索、DNS、扫描、告警、通知器、数据集、组织、账户及工具。

2.0.0 是继早期 OpenClaw 专用 v1 版本之后的重大可移植重构。该版本改变了安装方式、命令结构、输出、API 覆盖和安全行为；现有工作流应迁移到下文记录的分组 CLI。

[官方 API 快照](references/official-api-snapshot.yaml) 记录操作、来源、获取日期和规范化哈希；[覆盖清单](references/api-coverage.yaml) 把每个操作映射到唯一 CLI 命令及 pytest 契约节点。默认测试完全离线，不需要 API 密钥，也不会消耗积分、扫描目标、打开真实数据流、下载数据或修改账户。

项目以公开 HTTP API 为准。SDK 兼容信息及响应结构分别见以下文档：[SDK 基线](references/sdk-baseline.md)、[仅 SDK 操作](references/sdk-only.md)、[数据结构](references/data-schemas.md)。这些 Skill 运行参考采用单一英文规范版本，避免双份内容漂移。

## 安装与认证

需要 Python 3.10 或更高版本：

```bash
python -m pip install shodan-skill
shodan-skill --version
shodan-skill --help
```

经过审阅的本地仓库可以使用 `python -m pip install .`，开发安装使用 `python -m pip install -e ".[dev]"`。通过 `SHODAN_API_KEY` 提供密钥，也可复用 `~/.shodan/api_key` 或 `~/.config/shodan/api_key`；两者同时存在时优先使用旧路径。不要把密钥写入源代码、提示词、测试夹具或可能被记录的命令参数。

## 运行控制

程序不会继承 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 或 `.netrc`，以免 Shodan 查询认证意外流向环境代理。代理只能通过 `SHODAN_PROXY` 或根选项 `--proxy` 显式配置，并且必须是绝对 HTTP(S) URL。含凭据的代理 URL 应优先放在环境变量中。

连接、读取、写入、连接池和流空闲超时分别由 `SHODAN_CONNECT_TIMEOUT`、`SHODAN_READ_TIMEOUT`、`SHODAN_WRITE_TIMEOUT`、`SHODAN_POOL_TIMEOUT`、`SHODAN_STREAM_TIMEOUT` 控制，默认值依次为 10、30、30、10、60 秒。`SHODAN_RETRIES` 默认为 2，允许 0 至 5。对应根选项必须写在命令组之前：

```bash
shodan-skill --read-timeout 45 --retries 1 host info 8.8.8.8
```

## 命令组

`host`、`search`、`scan`、`alert`、`notifier`、`query`、`dns`、`tools`、`account`、`stream`、`trends`、`exploits`、`data`、`org` 和 `reference` 分别处理主机、检索、扫描、告警、通知器、共享查询、DNS、工具、账户、实时流、趋势、漏洞利用、企业数据、组织及本地参考。

使用 `shodan-skill account api-info` 查询 API 套餐、用量限制以及剩余查询或扫描积分。`shodan-skill account profile` 仅用于会员和账户资料；其中通用的 `credits` 字段不能作为 API 查询或扫描积分余额。

```bash
shodan-skill host info 8.8.8.8
shodan-skill search hosts "product:nginx" --facets country:5
shodan-skill search count "port:443"
shodan-skill dns domain example.com --history
shodan-skill exploits search apache --page 2 --omit-code
shodan-skill stream ports 22,443 --limit 10
```

用 `shodan-skill GROUP ACTION --help` 查看完整参数。旧下划线命令仍作为弃用兼容别名保留。

## 安全与账户要求

CLI 与 Skill 默认采用 `direct` 模式。明确输入命令或提出操作请求后，程序经过本地校验便直接执行；积分消耗、状态变更、下载、扫描和监控网络均不再二次确认。具有确定性预览的操作会把预览写入 stderr，然后立即继续。使用根级 `--dry-run` 可只校验并预览而不发送请求。

设置 `SHODAN_SAFETY_MODE=strict` 或使用根级 `--safety-mode strict` 可恢复旧确认行为。严格模式要求 `--confirm` 或 `--yes`，扫描和监控网络还要求 `--acknowledge-authorization`。这些参数在直接模式下仍作为脚本兼容选项接受；`--y`、`--conf`、`--ack` 等缩写仍会被拒绝。

搜索过滤器、额外页、DNS 域查询和扫描可能消耗积分。互联网扫描、全局或自定义流、Trends、数据集和组织操作需要相应 Enterprise 权限。已配置 API 密钥不会触发用户未请求的操作。消耗积分的 GET 不自动重试；无积分 GET 保留有界重试及 `Retry-After` 处理。

下载先写入 `.part` 文件，可通过 HTTP Range 有界续传，默认校验大小和可用的 SHA-1，且不会覆盖下载期间新出现的目标文件。已有部分文件和最终文件需要显式选择 `--resume` 或 `--overwrite`。

## 输出与退出码

非流式 stdout 默认输出稳定 JSON 信封；流默认逐行输出 JSON，选择 `--stream-format sse` 时输出 SSE `data:` 事件。可按适用场景选择 `--output json`、`--output jsonl` 或 `--output human`。`--debug` 请求 Shodan 的丢弃诊断；有限超时的数据流会关闭服务端 heartbeat，避免空闲心跳掩盖超时。诊断及预览写入 stderr。`credit_impact` 为 `none`、`conditional`、`query`、`scan` 或 `unknown`；`credits_estimated` 只在请求前可保守估算时填写；兼容字段 `credits_used` 为 `null`，不能理解为零消耗。

退出码：0 成功，2 用法或严格模式安全门，3 认证，4 授权或权限，5 积分，6 网络，7 API/下载/完整性，8 超时，9 操作中断，10 未预期内部错误。

API 密钥、凭据字段、Bearer 令牌、认证头、Cookie、通知器秘密、Webhook 和签名 URL 凭据均会递归脱敏，Shodan 密钥不会出现在显示的 URL 中。

## 文档漂移、平台与测试

`python scripts/refresh_official_snapshot.py --check` 只读取官方开发者网页，不调用 Shodan API。确认官方文档变化后，使用 `--write` 更新快照，再审查覆盖清单并运行 `python scripts/verify_coverage.py --require-complete`。

仓库根目录的 [SKILL.md](SKILL.md) 是对外目录收录的规范入口；`platforms/` 中的文件是生成的安装 Bundle，不得作为多个独立 Skill 重复提交。

平台适配器由根目录的规范 `SKILL.md` 生成：

```bash
python scripts/build_bundles.py
python scripts/verify_skill.py
python scripts/install_skill.py --platform openclaw
python scripts/install_skill.py --platform codex
python scripts/install_skill.py --platform claude-code
python scripts/install_skill.py --platform hermes
```

安装器不会在未确认时覆盖现有 Skill；CLI 包需另行安装。

完整离线门禁包括 pytest、90% 覆盖率、Ruff、mypy、覆盖清单校验、Skill/发布校验和构建。实时验证默认关闭，并要求显式用户授权以及相互独立的环境变量和 pytest 门禁：

- 授权的只读检查需要 `SHODAN_LIVE_TESTS=1` 和 `--allow-live-shodan`。
- 消耗积分的检查还需要 `--allow-shodan-credits`。
- 另行授权的状态变更需要 `SHODAN_MUTATING_TESTS=1` 和 `--allow-shodan-mutations`。
- Enterprise 检查需要 `SHODAN_ENTERPRISE_TESTS=1` 和相应账户权限。
- 扫描或监控测试的 `SHODAN_TEST_TARGETS` 只能包含已授权目标。

这些门禁在操作类别重叠时必须累积满足。任何单个环境变量、pytest 参数、已配置密钥或账户权限都不能授权真实扫描、账户变更、流、下载或积分消耗。

CI 在 Linux 上执行一次完整的质量、覆盖率、bundle 漂移和构建门禁，并通过独立矩阵覆盖所有支持的 Python 与操作系统组合。推送 `v2.0.1` 这类版本标签后，发布工作流会校验标签和全部发布门禁，由隔离的 Trusted Publishing 作业把 Python 制品上传到 PyPI，然后才创建或更新 GitHub Release 并附加已验证制品。

双语说明书使用独立的锁定依赖构建和校验：

```bash
python scripts/verify_manual.py
python -m pip install --requirement requirements-docs.txt
python -m mkdocs build --strict
```

安全问题请按照根目录的正式英文 [安全策略](SECURITY.md) 私密报告；不要在公开 Issue 中粘贴真实密钥、私有目标或敏感响应。

## 许可证

MIT
