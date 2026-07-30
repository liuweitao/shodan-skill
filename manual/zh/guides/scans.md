# 扫描

只能扫描你有权评估的目标。执行前核对准确的目标列表，不得扩大用户要求的 CIDR 或地址集合。

## 参考和状态命令

```bash
shodan-skill scan ports
shodan-skill scan protocols
shodan-skill scan list --page 1
shodan-skill scan status SCAN_ID
```

端口和协议命令返回 Shodan 参考数据；列表和状态命令读取已有扫描元数据。

## 提交按需扫描

先进行不发送请求的预演：

```bash
shodan-skill --dry-run scan submit 192.0.2.10 --service 443:https
```

执行明确要求的扫描：

```bash
shodan-skill scan submit 192.0.2.10 --service 443:https
```

目标可以是经过校验的 IP 地址和 CIDR。重复使用 `--service PORT:PROTOCOL` 可以指定多个自定义服务。`--force` 请求与官方 SDK 兼容的 Enterprise 重新扫描行为，并会显示在预览中。按需扫描可能消耗扫描积分。

## 互联网范围扫描

```bash
shodan-skill --dry-run scan internet 443 https
shodan-skill scan internet 443 https
```

互联网范围扫描需要 Enterprise 权限，并具有广泛外部影响。direct 模式执行前，确定性预览会标明操作、目标范围、积分类别和可逆性。

严格模式下，应在叶子命令后添加 `--confirm --acknowledge-authorization`。direct 模式不要求这些兼容选项。

动态标识符和路径片段会在本地校验，防止分隔符或路径穿越片段改变请求端点。

官方 REST 参考：<https://developer.shodan.io/api>
