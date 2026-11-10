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

每周官方文档巡检仍会在真实漂移时失败。先查看任务摘要并下载 `official-documentation-review` 产物，
其中包含候选快照、文本变化说明和新增／删除的接口清单。临时网络故障及部分 HTTP 错误最多重试三次，
永久 HTTP 错误立即失败；抓取失败不会覆盖已接受的快照。

即使接口路径完全相同，也必须审阅变化来源：文本哈希无法判断参数、权限、积分及响应契约的语义变化。
接受候选快照后，同步 `references/api-coverage.yaml` 的 `official_retrieved` 与快照抓取日期，再运行 `python scripts/build_bundles.py` 同步各平台副本并执行全部验证。
`--write` 在内容未变时不会更新抓取日期，避免产生每周仅日期变化的提交。

每条 PR 都验证 release 依赖、隔离 wheel 安装及真实 CycloneDX SBOM 生成。
`Required CI` 汇总质量检查、九种系统／Python 组合与发布冒烟测试，前置任务失败或跳过都会使汇总失败。
双语文档构建改为在全部 PR 上运行，适合作为必需检查。Dependabot 仅将次版本和补丁更新分组，
主版本更新单独保留人工审阅。

### 待仓库所有者批准的写权限自动化

当前改动维持工作流对仓库内容的只读权限，没有启用自动合并、自动批准或自动创建快照 PR。
建议批准以下明确范围后再实施：

1. 开启仓库 `allow_auto_merge`，保护 `master` 且同样约束管理员，要求分支及时更新并通过
   `Required CI`、`Build bilingual manual`、`Analyze Python`（GitHub Actions 应用 ID 15368）
   以及 `CodeQL`（GitHub Code Scanning 应用 ID 57789），禁止强推和删除分支，不绕过检查。
2. 使用 `pull_request_target` 处理同仓库、目标为默认分支的 Dependabot PR，不检出或执行 PR 代码。
   固定 `dependabot/fetch-metadata` 的完整提交 SHA 并保留签名校验，仅对已验证、无维护者变更的
   semver 补丁／次版本更新执行 `gh pr merge --auto --squash --match-head-commit`，等待必需检查放行。
   元数据未知、主版本更新均不自动合并；保护规则未配置时必须拒绝执行，不自动批准代码。
3. 仅给文档巡检任务增加 `contents: write` 和 `pull-requests: write`，维护一个固定分支和一条更新 PR。
   修改范围限于官方快照、覆盖清单的抓取日期及同步的平台副本，附漂移报告，运行正常 CI，保留人工语义审阅，禁止自动合并。
   按 GitHub 事件规则，`GITHUB_TOKEN` 创建的 PR 可能需要先批准才能运行检查；如需无人值守，
   使用权限受限的独立 GitHub App 令牌，不把个人令牌写入代码，也不绕过 CI。

不让自动化任意修补业务代码、放宽失败断言、调用真实 Shodan API、消耗积分、自动接受主版本升级或发布。
发布继续沿用现有标签及环境门禁。失败测试应触发定位，不能成为自动降低验证标准的理由。
