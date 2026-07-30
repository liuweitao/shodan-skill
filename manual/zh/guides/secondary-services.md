# Trends 与 Exploits

这两个命令组使用独立服务主机，不应路由到普通主机搜索端点。

## Trends

```bash
shodan-skill trends search "product:nginx" --facets country:10
shodan-skill trends filters
shodan-skill trends facets
```

Trends 使用 `https://trends.shodan.io`，需要相应的 Trends 或 Enterprise 权限。已记录的搜索契约只包含 `query` 和可选 `facets`。CLI 不会虚构文档中不存在的时间范围参数。

官方参考：<https://developer.shodan.io/api/trends>

## Exploits

```bash
shodan-skill exploits search apache --page 2 --facets platform:5
shodan-skill exploits count apache --facets platform:5
```

Exploits 使用 `https://exploits.shodan.io/api`。`--limit N` 只在本地截断搜索匹配项，不会作为未支持的 API 参数发送。漏洞利用代码默认保留，只有在明确要求时才缩减：

```bash
shodan-skill exploits search apache --omit-code
shodan-skill exploits search apache --truncate-code 2000
```

官方参考：

- <https://developer.shodan.io/api/exploits/rest>
- <https://developer.shodan.io/api/exploit-specification>
