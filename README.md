# XrayR

Vergelab 维护的 Xray 后端，用来把一块节点同时接到多种面板。命令和二进制名仍是 `XrayR`，已有的安装目录、systemd 单元和脚本不用改名。

当前版本：**0.3**

- 代码仓库：https://github.com/Vergelab/XrayR
- 安装脚本与发布：https://github.com/Vergelab/xrayr-release
- 容器镜像：`ghcr.io/vergelab/xrayr`
- English: [README-en.md](README-en.md)

`XrayR version` 会打印 `XrayR 0.3 (Vergelab)`。

## 特点

- 支持 VMess、VLESS、Trojan、Shadowsocks。
- 一个进程可以同时对接多块面板、多个节点。
- 支持在线 IP 限制，以及节点端口、用户两级限速。
- 修改配置后自动重载。
- 可自动申请和续签 TLS 证书。

## 功能

| 功能 | VMess | VLESS | Trojan | Shadowsocks |
| --- | --- | --- | --- | --- |
| 获取节点信息 | √ | √ | √ | √ |
| 获取用户信息 | √ | √ | √ | √ |
| 用户流量统计 | √ | √ | √ | √ |
| 服务器信息上报 | √ | √ | √ | √（NewV2board 不上报，接口直接返回成功） |
| 自动申请 TLS 证书 | √ | √ | √ | √ |
| 自动续签 TLS 证书 | √ | √ | √ | √ |
| 在线人数统计 | √ | √ | √ | √ |
| 在线用户限制 | √ | √ | √ | √（见下方设备数说明） |
| 审计规则 | √ | √ | √ | √ |
| 节点端口限速 | √ | √ | √ | √ |
| 按用户限速 | √ | √ | √ | √ |
| 自定义 DNS | √ | √ | √ | √ |

## 支持的面板

配置里的 `PanelType` 取下表中的类型名。

| 面板 | VMess | VLESS | Trojan | Shadowsocks |
| --- | --- | --- | --- | --- |
| SSpanel（sspanel-uim） | √ | √ | √ | √（单端口多用户和 V2Ray-Plugin） |
| NewV2board | √ | √ | √ | √ |
| [PMPanel](https://github.com/ByteInternetHK/PMPanel) | √ | √ | √ | √ |
| [ProxyPanel](https://github.com/ProxyPanel/ProxyPanel) | √ | √ | √ | √ |
| [WHMCS (V2RaySocks)](https://v2raysocks.doxtex.com/) | √ | √ | √ | √ |
| [GoV2Panel](https://github.com/pingProMax/gov2panel) | √ | √ | √ | √ |
| [BunPanel](https://github.com/pennyMorant/bunpanel-release) | √ | √ | √ | √ |

## 安装

### 一键安装

```bash
wget -N https://raw.githubusercontent.com/Vergelab/xrayr-release/master/install.sh && bash install.sh
```

### 手动安装

从 [Releases](https://github.com/Vergelab/xrayr-release/releases) 下载对应平台的压缩包。Linux amd64 的文件名是 `XrayR-linux-64.zip`。压缩包内是 `XrayR` 二进制、`config.yml`、`custom_inbound.json`、`custom_outbound.json`、`dns.json`、`route.json`、`rulelist`、`geoip.dat`、`geosite.dat`、`LICENSE` 和 `README.md`。

```bash
unzip XrayR-linux-64.zip -d /usr/local/XrayR
cd /usr/local/XrayR
# 按节点修改 config.yml 后启动
./XrayR
```

### Docker

镜像在本仓库发布 Release 时构建，名称为 `ghcr.io/vergelab/xrayr`。把配置挂到 `/etc/XrayR/config.yml`：

```bash
docker pull ghcr.io/vergelab/xrayr
docker run -d --name xrayr --network host \
  -v /etc/XrayR:/etc/XrayR \
  ghcr.io/vergelab/xrayr
```

## 配置

示例配置在 [`release/config/config.yml.example`](release/config/config.yml.example)。DNS、路由、入站和出站的字段沿用 Xray 核心的配置格式，示例文件里的注释给出了对应说明。

## 路由

发布包里的 `route.json` 把全部 TCP/UDP 送到 `direct`。`custom_outbound.json` 里的 `direct` 是 freedom 直连，没有 WARP 密钥。以前带示例 WARP 密钥的文件改名为 [`route.json.example`](release/config/route.json.example) 和 [`custom_outbound.json.example`](release/config/custom_outbound.json.example)，不能直接当生产配置。

## NewV2board / Xboard

- 服务器状态不上报。`ReportNodeStatus` 固定返回成功，Xboard 0.1.1 的节点接口没有对应的状态写入。
- 设备数按「本节点上该用户的不同来源 IP」计算，再叠加面板 alive 数据（如果面板提供）。Xboard 0.1.1-dev 的用户列表没有 `device_limit` 字段，也没有 `alivelist`（请求会 404，只记一次日志）。要限制设备数，在节点配置里写 `DeviceLimit`。用户 JSON 里如果带了 `device_limit`，且本地 `DeviceLimit` 为 0，就用用户上的值。`alivelist` 拉取失败时保留上一份成功的计数，不会清成空表。
- `RuleListPath` 每一行是未锚定的正则，`.` 匹配任意字符，并且全部当作拦截规则。编译失败的行会跳过并写日志。
- 面板 `flow` 为空时使用本地 `ApiConfig.VlessFlow`。NewV2board 示例是 `xtls-rprx-vision`，并打开 `DisableLocalREALITYConfig`。面板声明了 REALITY 但没有套用到入站时，节点构建失败，不会退回 TLS 或明文。
- API token 仍放在查询参数里。Xboard 0.1.1-dev 的 `Server` 中间件用 `$request->validate(['token' => required])`，只认查询参数和请求体，不认 header。
- `ControllerConfig.REALITYAllowNonPQClients` 默认 true（不写也是 true）。xray-core v26.10.31 自带的 REALITY 会把没有 `X25519MLKEM768` 的 ClientHello 直接交给伪装站，于是 edge、ios、qq、mihomo 默认配置和 sing-box 都连不上，只有 chrome / firefox / safari 可以。打开之后，只有 X25519 的 hello 用这把 X25519 做 REALITY 认证；客户端如果带了 `X25519MLKEM768`，TLS 仍然协商这个混合组，不会降级。代价是：带对 shortId 的非 PQ hello 会完成握手，而不再落到伪装站，主动探测可以据此和上游 Xray 区分开。要和上游一致就写成 false。android 和 360 两种模式都不行，它们没有 TLS 1.3 key share。这个值是进程级的（xray-core 的 REALITY protobuf 没有逐入站字段）；同一进程里节点不一致时用第一个并写日志。改配置热重载会在新的监听开始前生效。

## 免责声明

本程序供学习与研究使用。维护者不保证其可用性，也不对使用本软件造成的任何后果负责。

## 许可证

本项目以 Mozilla Public License 2.0（见 [LICENSE](LICENSE)）授权，派生自 XrayR。
