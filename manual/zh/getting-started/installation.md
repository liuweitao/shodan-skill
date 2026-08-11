# 安装与认证

## 环境要求

- Python 3.10 或更高版本
- Shodan 账户和 API Key
- 请求操作所需的积分或服务权限

从 PyPI 安装当前版本：

```bash
python -m pip install shodan-skill
shodan-skill --help
shodan-skill --version
```

从经过审阅的本地仓库安装时，把第一条命令替换为 `python -m pip install .`；开发环境可以使用 `python -m pip install -e ".[dev]"`。

安装后的命令不依赖 Skill 目录的位置。CLI Python 包和 Agent 平台 Bundle 应分别安装。

## API Key 查找顺序

CLI 按以下顺序检查：

1. `SHODAN_API_KEY`
2. `~/.shodan/api_key`
3. `~/.config/shodan/api_key`

两个文件同时存在时，旧路径 `~/.shodan/api_key` 优先。应限制文件仅供预期用户读取。不得把真实密钥放进提示词、仓库、测试夹具、截图、URL 或可能被记录的命令参数。

## 验证认证

```bash
shodan-skill account api-info
shodan-skill account profile
```

退出码 `3` 表示认证失败。退出码 `4` 通常表示密钥有效，但账户缺少相应权限。退出码 `5` 表示积分错误。

## 升级和卸载

继续使用最初经过信任的安装来源。PyPI 安装可以使用以下命令升级：

```bash
python -m pip install --upgrade shodan-skill
```

从本地仓库升级时，应先拉取并审阅变更。卸载命令为：

```bash
python -m pip uninstall shodan-skill
```

Agent Bundle 是各平台发现目录中的独立副本。卸载 Python 包不会移除 Bundle，删除 Bundle 也不会卸载 CLI。

## 代理注意事项

传输层有意忽略环境代理变量和 `.netrc`。确实需要经过审阅的代理时，使用 `SHODAN_PROXY` 或根选项 `--proxy`。代理可能看到 Shodan 查询认证信息，因此不得使用不可信代理。
