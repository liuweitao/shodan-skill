# 主机发现与 DNS

## 主机详情与搜索

读取主机记录，并可选择历史或精简响应：

```bash
shodan-skill host info 8.8.8.8
shodan-skill host info 8.8.8.8 --history --minify
```

搜索、计数或查看当前查询元数据：

```bash
shodan-skill search hosts "product:nginx" --page 1 --facets country:5
shodan-skill search count "port:443" --facets country:5
shodan-skill search facets
shodan-skill search filters
shodan-skill search tokens "product:nginx"
```

`search hosts --limit N` 只在本地截断返回的匹配项，不会重写已记录的 API 请求。`--fields`、`--facets`、`--minify` 和分页参数会保持原意转发。过滤器和分面应查询动态端点，不要依赖复制的静态清单。

## 社区查询目录

```bash
shodan-skill query list --page 1 --sort timestamp --order desc
shodan-skill query search nginx --page 1
shodan-skill query tags --limit 10
```

这些命令用于浏览社区查询目录。保存的查询只是需要审阅的输入，并不构成扫描或监控目标的授权。

## DNS

```bash
shodan-skill dns domain example.com --history --type A --page 1
shodan-skill dns resolve example.com,example.net
shodan-skill dns reverse 8.8.8.8,1.1.1.1
```

域名信息每次查询消耗一个查询积分。解析和反向解析属于只读操作。程序会在本地校验域名、IPv4/IPv6、记录类型和正数页码。

## 账户、工具和本地参考

```bash
shodan-skill account profile
shodan-skill account api-info
shodan-skill tools httpheaders
shodan-skill tools myip
shodan-skill reference filters
shodan-skill reference datapedia
```

查询套餐及剩余查询或扫描积分应使用 `account api-info`。其他响应中的通用 `credits` 字段不能作为权威余额。返回的请求头、账户详情和 DNS 信息可能敏感，应保留默认脱敏行为。

官方 REST 参考：<https://developer.shodan.io/api>
