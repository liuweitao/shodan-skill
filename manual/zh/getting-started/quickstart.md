# 快速开始

## 1. 安装

需要 Python 3.10 或更高版本。从 PyPI 安装当前版本：

```bash
python -m pip install shodan-skill
shodan-skill --version
```

经过审阅的本地仓库或开发环境可以使用：

```bash
python -m pip install .
python -m pip install -e ".[dev]"
```

## 2. 配置 API Key

优先使用环境变量，避免密钥进入源文件或命令历史：

```bash
export SHODAN_API_KEY="your-key"
```

PowerShell：

```powershell
$env:SHODAN_API_KEY = "your-key"
```

CLI 也可以读取 `~/.shodan/api_key` 或 `~/.config/shodan/api_key`。优先级和安全处理建议见[安装与认证](installation.md)。

## 3. 检查账户并执行只读请求

```bash
shodan-skill account api-info
shodan-skill host info 8.8.8.8
```

`account api-info` 返回套餐及剩余查询或扫描积分信息。它不同于返回成员和资料信息的 `account profile`。

## 4. 先预演搜索

根选项必须放在命令组之前：

```bash
shodan-skill --dry-run search hosts "product:nginx" --facets country:5
shodan-skill search hosts "product:nginx" --facets country:5
```

第一条命令只校验请求并显示积分预览，不创建传输连接；第二条命令实际执行。带过滤器的搜索以及第一页之后的分页可能消耗查询积分。

## 5. 读取结果

非流式 stdout 默认使用稳定 JSON 信封。诊断和预览写入 stderr，因此脚本可以独立解析 stdout。交互查看可使用 `--output human`，需要逐行输出时可以使用 `--output jsonl`。

下一步建议阅读[安全与权限](../concepts/safety.md)和[任务配方](../recipes.md)。
