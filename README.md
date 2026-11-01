# XrayR

Vergelab 维护的 Xray 后端，用来把一块节点同时接到多种面板。命令和二进制名仍是 `XrayR`，已有的安装目录、systemd 单元和脚本不用改名。

当前版本：**0.1**

- 代码仓库：https://github.com/Vergelab/XrayR
- 安装脚本与发布：https://github.com/Vergelab/xrayr-release
- 容器镜像：`ghcr.io/vergelab/xrayr`
- English: [README-en.md](README-en.md)

`XrayR version` 会打印 `XrayR 0.1 (Vergelab)`。

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
| 服务器信息上报 | √ | √ | √ | √ |
| 自动申请 TLS 证书 | √ | √ | √ | √ |
| 自动续签 TLS 证书 | √ | √ | √ | √ |
| 在线人数统计 | √ | √ | √ | √ |
| 在线用户限制 | √ | √ | √ | √ |
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

## 免责声明

本程序供学习与研究使用。维护者不保证其可用性，也不对使用本软件造成的任何后果负责。

## 许可证

本项目以 Mozilla Public License 2.0（见 [LICENSE](LICENSE)）授权，派生自 XrayR。
