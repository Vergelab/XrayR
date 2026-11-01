# 更新日志

## 0.4

- `REALITYAllowNonPQClients` 改到配置文件顶层，与 `Log`、`Nodes` 同级。不写仍然是 true。启动和热重载时写入一次，对整个进程生效。
- 节点上的 `ControllerConfig.REALITYAllowNonPQClients` 仍能解析，旧配置不会坏。顶层没写时按原来的规则用第一个节点的值，并打一条弃用警告，提示改用顶层键。两处都写时以顶层为准；取值不同则打一条日志。
- 示例配置改回上游那种短行内注释。开关只在顶层出现一次。

## 0.3

- 接受没有 `X25519MLKEM768`、只有 X25519 的 REALITY ClientHello。
  xray-core v26.10.31 使用的 `github.com/xtls/reality`（提交 `83f621788ca8`，行为来自 XTLS/REALITY `8cdf7bf`）在看不到这个混合密钥组时会把连接原样交给伪装站。结果是 edge、ios、qq、mihomo 默认配置以及 sing-box 都连不上，只有 Xray-core 上的 chrome / firefox / safari 可以。面板若在 chrome / firefox / safari / ios / edge / qq 之间随机指纹，大约一半客户端会失败。
- 仓库内放入上述 reality 的补丁副本（`third_party/reality`），用 `go.mod` 的 `replace` 接上。补丁只改这一处：允许时用独立的 X25519 密钥份额做 REALITY 认证。客户端如果仍然发送 `X25519MLKEM768`，TLS 握手继续协商这个混合组，不会降级。
- 新增节点配置 `ControllerConfig.REALITYAllowNonPQClients`。不写或者写成 true 都会接受非 PQ 客户端；写成 false 恢复上游行为。NewV2board 示例里显式写成 true。
  xray-core 的 REALITY 配置是 protobuf，没有可以逐入站传递的字段，不 fork xray-core 就塞不进 `reality.Config`。因此这个开关是进程级的，在启动和热重载时、新监听接受连接之前写入。同一进程里多个节点取值不一致时，采用第一个节点的值并写一条警告。热重载会关掉旧实例再按新配置启动，开关随之更新。
- android 和 360 仍然不可用：这两种指纹没有 TLS 1.3 key share。面板也不会下发它们。
- 修正 `service/controller/inboundbuilder.go` 里的注释。原先把 ios / android / edge / 360 / qq 写成可用的指纹。实际上在上游模式下只有带 `X25519MLKEM768` 的 chrome / firefox / safari 能过；打开本开关后 ios / edge / qq 可以，android / 360 仍然不行。
- NewV2board 的 REALITY `dest` 在已经带端口时不再追加 `server_port`（`www.example.com:443` 不会变成非法的 `www.example.com:443:8443`）。没写端口时才补上，空端口仍是 443。IPv6 会收成 `[addr]:port`，已经带方括号但没有端口的地址不会变成 `[[addr]]:port`。

## 0.2

- 基于 xray-core v26.10.31 的 Vergelab 维护版本。
