# 命令速查

这里提供紧凑的命令路径和选项索引，不能替代 `shodan-skill GROUP ACTION --help`。`--output`、`--dry-run`、超时、重试、代理和安全模式等根选项必须写在命令组之前。

## 主机和搜索

| 命令 | 主要叶子参数 |
|---|---|
| `shodan-skill host info IP` | `--history`、`--minify` |
| `shodan-skill search hosts QUERY` | `--page`、`--facets`、`--[no-]minify`、`--fields`、`--limit` |
| `shodan-skill search count QUERY` | `--facets` |
| `shodan-skill search facets` | 无 |
| `shodan-skill search filters` | 无 |
| `shodan-skill search tokens QUERY` | 无 |

## 扫描

| 命令 | 主要叶子参数 |
|---|---|
| `shodan-skill scan submit IPS` | `--service`、`--force` |
| `shodan-skill scan internet PORT PROTOCOL` | Enterprise |
| `shodan-skill scan list` | `--page` |
| `shodan-skill scan status ID` | 无 |
| `shodan-skill scan ports` | 无 |
| `shodan-skill scan protocols` | 无 |

## 告警

| 命令 | 主要叶子参数 |
|---|---|
| `shodan-skill alert list` | `--[no-]include-expired` |
| `shodan-skill alert info ID` | `--[no-]include-expired` |
| `shodan-skill alert triggers` | 无 |
| `shodan-skill alert create NAME NETWORKS` | `--expires` |
| `shodan-skill alert edit ID NETWORKS` | 无 |
| `shodan-skill alert delete ID` | 破坏性 |
| `shodan-skill alert trigger enable ID TRIGGER` | 无 |
| `shodan-skill alert trigger disable ID TRIGGER` | 无 |
| `shodan-skill alert trigger ignore ID TRIGGER SERVICE` | 无 |
| `shodan-skill alert trigger unignore ID TRIGGER SERVICE` | 无 |
| `shodan-skill alert notifier add ID NOTIFIER_ID` | 无 |
| `shodan-skill alert notifier remove ID NOTIFIER_ID` | 无 |

## 通知器

| 命令 | 主要叶子参数 |
|---|---|
| `shodan-skill notifier list` | 无 |
| `shodan-skill notifier info ID` | 无 |
| `shodan-skill notifier providers` | 无 |
| `shodan-skill notifier create PROVIDER` | `--arg NAME=VALUE`、必需的 `--description` |
| `shodan-skill notifier edit ID` | `--arg NAME=VALUE` |
| `shodan-skill notifier delete ID` | 破坏性 |

## 社区查询、DNS、账户和工具

| 命令 | 主要叶子参数 |
|---|---|
| `shodan-skill query list` | `--page`、`--sort`、`--order` |
| `shodan-skill query search QUERY` | `--page` |
| `shodan-skill query tags` | `--limit` |
| `shodan-skill dns domain DOMAIN` | `--history`、`--type`、`--page` |
| `shodan-skill dns resolve HOSTNAMES` | 逗号分隔 |
| `shodan-skill dns reverse IPS` | 逗号分隔 |
| `shodan-skill account profile` | 无 |
| `shodan-skill account api-info` | 无 |
| `shodan-skill tools httpheaders` | 无 |
| `shodan-skill tools myip` | 无 |

## Streaming

所有数据流都支持 `--limit`、`--stream-format`、`--debug`、`--reconnect` 和 `--max-reconnects`。

| 命令 | 选择器 |
|---|---|
| `shodan-skill stream banners` | 全局 Banner |
| `shodan-skill stream asn ASNS` | 逗号分隔 ASN |
| `shodan-skill stream countries COUNTRIES` | 逗号分隔国家代码 |
| `shodan-skill stream ports PORTS` | 逗号分隔端口 |
| `shodan-skill stream vulns VULNS` | 逗号分隔 CVE |
| `shodan-skill stream alerts` | 账户告警数据流 |
| `shodan-skill stream alert ID` | 单个告警数据流 |
| `shodan-skill stream custom QUERY` | 自定义查询 |

## Trends 和 Exploits

| 命令 | 主要叶子参数 |
|---|---|
| `shodan-skill trends search QUERY` | `--facets` |
| `shodan-skill trends filters` | 无 |
| `shodan-skill trends facets` | 无 |
| `shodan-skill exploits search QUERY` | `--page`、`--facets`、`--limit`、`--omit-code`、`--truncate-code` |
| `shodan-skill exploits count QUERY` | `--facets` |

## Enterprise 数据和组织

| 命令 | 主要叶子参数 |
|---|---|
| `shodan-skill data list` | 无 |
| `shodan-skill data files DATASET` | 无 |
| `shodan-skill data download DATASET NAME` | `--output-file`、`--resume`、`--overwrite`、`--[no-]verify`、`--chunk-size` |
| `shodan-skill org info` | 无 |
| `shodan-skill org member add USER` | `--[no-]notify` |
| `shodan-skill org member remove USER` | 破坏性 |

## 本地参考

| 命令 | 结果 |
|---|---|
| `shodan-skill reference filters` | 当前官方过滤器参考链接 |
| `shodan-skill reference datapedia` | Datapedia 概览、Schema 和变更记录链接 |

状态变更命令还会在适用处接受严格模式兼容选项。准确契约以已安装版本的叶子命令帮助为准。
