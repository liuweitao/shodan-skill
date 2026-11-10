# 故障排查

## 命令或选项被拒绝

根选项必须放在命令组之前：

```bash
shodan-skill --output human --read-timeout 45 host info 8.8.8.8
```

使用 `shodan-skill GROUP ACTION --help` 查看已安装版本的参数契约。程序有意拒绝长选项缩写。已弃用的下划线命令名可能发出兼容性警告。

## 认证失败，退出码 3

检查 `SHODAN_API_KEY`、`~/.shodan/api_key` 或 `~/.config/shodan/api_key` 是否包含预期密钥。诊断时不要打印密钥。如果两个文件都存在，旧的 `.shodan` 路径优先。

## 授权失败，退出码 4

账户已经认证，但缺少权限。常见情况包括全局数据流、Trends、数据集、组织成员和互联网范围扫描。使用 `shodan-skill account api-info` 确认账户套餐。

## 积分失败，退出码 5

检查账户余额和请求操作。消耗积分的 GET 不会自动重试。在审阅服务结果和账户状态前，不要假定失败请求可以安全重复。

## 网络或超时失败，退出码 6 和 8

CLI 忽略环境代理。网络确实需要代理时，设置经过审阅的 `SHODAN_PROXY` 或根选项 `--proxy`。只有在预期服务行为确有需要时才调整有限的连接、读取或数据流超时。

数据流在达到 `--limit` 前正常 EOF 仍属于网络失败。需要继续时使用有界重连。

## 下载或完整性失败，退出码 7

需要续传时保留 `.part` 文件；只有在可以接受替换时才使用 `--overwrite`。大小或 SHA-1 不匹配会阻止最终完成。除非明确接受风险且元数据确实不适用，否则不要使用 `--no-verify`。

## 严格模式门禁，退出码 2

添加完整的 `--confirm` 或 `--yes`。扫描和监控网络还需要完整的 `--acknowledge-authorization`。如果预期策略是默认 direct 模式，也可以恢复 direct。

## 报告问题

提供版本、平台、移除秘密信息后的命令结构、退出码和脱敏 stderr。不得附带 API Key、代理凭据、签名 URL、通知器秘密信息、账户响应或未审阅的主机数据集。安全问题应通过仓库安全策略私下报告。

## 仓库维护与 Actions 失败

每周官方文档巡检对临时网络故障及部分 HTTP 错误最多重试三次。永久故障或无效文档会失败，
不会覆盖已接受的快照。每次运行产出 `official-documentation-review`，包含漂移报告与候选快照。

上游内容变化时，任务从 `automation/official-documentation` 固定分支维护一条审阅 PR。
写权限仅限仓库内容和 PR，提交范围限定为官方快照、覆盖清单及生成的平台副本；准备脚本仅修改
覆盖清单的抓取日期，保留接口实现及测试声明。因此，新增接口会让覆盖检查保持失败，直到人工完成
契约实现和审阅。没有内容变化、仅抓取日期变化时不创建 PR。审阅 PR 成功创建后，漂移作为已处理事件
结束巡检，避免每周重复报红；抓取或创建 PR 失败仍会明确报错，报告和候选快照即使失败也会上传。

即使接口路径相同，也必须审阅变化来源：哈希无法判断参数、权限、积分和响应契约的语义变化。
文档 PR 不自动合并。GitHub 可能要求先批准 `GITHUB_TOKEN` 所创建 PR 的检查；在人工审阅时放行检查，
不绕过必需检查，也不为省去这一审核步骤而加入个人令牌。

每条 PR 都验证 release 依赖、隔离 wheel 安装与真实 CycloneDX SBOM 生成。
`Required CI` 汇总质量检查、九种系统／Python 组合与发布冒烟测试；前置任务失败或跳过都会导致汇总失败。
双语文档在全部 PR 上构建，适合作为必需检查。Dependabot 仅将次版本和补丁更新分组，主版本升级单独审阅。

### 已批准的自动化与仓库设置

限定策略由 `dependabot-automerge.yml` 和 `docs-drift.yml` 实现。
所需仓库设置记录在 `.github/maintenance-settings.json`，需要具备 Administration:write、Actions:write
权限的凭据应用，或在 GitHub 对应设置页面完成：

1. 开启 `allow_auto_merge`，保护 `master` 并同样约束管理员。要求及时更新分支，且必须通过
   `Required CI`、`Build bilingual manual`、`Analyze Python`（GitHub Actions 应用 ID 15368）
   和 `CodeQL`（GitHub Code Scanning 应用 ID 57789）。要求解决讨论，禁止强推和删除分支。
2. 默认工作流权限保持只读，允许 Actions 创建 PR。GitHub 将开关命名为
   “Allow GitHub Actions to create and approve pull requests”，但本仓库工作流不会自动批准 PR。
   仅两个特定自动化任务声明所需的仓库内容／PR 写权限。
3. Dependabot 流程仅处理同仓库、目标为默认分支的非草稿 PR，不检出 PR 代码。
   固定版本的元数据 Action 验证 Dependabot 身份及提交签名。仅已验证、无维护者变更的配置生态内
   semver 补丁／次版本更新可进入自动合并队列。
4. 执行 `gh pr merge --auto --squash --match-head-commit` 前，通过 GraphQL 核对实际保护规则、
   必需检查及其应用来源。规则缺失、不可读取或减弱时拒绝自动合并。主版本及未知元数据保留人工处理。
   GitHub 原生分支保护负责在合并时执行最新检查门禁。

官方依据：[Dependabot 自动化](https://docs.github.com/en/code-security/tutorials/secure-your-dependencies/automate-dependabot-with-actions)
及[工作流事件与令牌规则](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow)。

不自动任意修补业务代码、放宽失败断言、调用真实 Shodan API、消耗积分、接受主版本升级或发布。
发布继续沿用现有版本标签及环境门禁。
