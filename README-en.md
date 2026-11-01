# XrayR

Xray backend maintained by Vergelab. One process can serve several panels and nodes. The command and binary name stay `XrayR`, so existing install paths, systemd units, and scripts keep working.

Current version: **0.1**

- Source: https://github.com/Vergelab/XrayR
- Install scripts and releases: https://github.com/Vergelab/xrayr-release
- Container image: `ghcr.io/vergelab/xrayr`
- 中文: [README.md](README.md)

`XrayR version` prints `XrayR 0.1 (Vergelab)`.

## Features

- VMess, VLESS, Trojan, and Shadowsocks.
- One process can attach to multiple panels and nodes.
- Online IP limits, plus per-node and per-user speed limits.
- Reloads when the config file changes.
- Can issue and renew TLS certificates.

## Capabilities

| Capability | VMess | VLESS | Trojan | Shadowsocks |
| --- | --- | --- | --- | --- |
| Node info | √ | √ | √ | √ |
| User info | √ | √ | √ | √ |
| User traffic | √ | √ | √ | √ |
| Server status report | √ | √ | √ | √ |
| Issue TLS certificate | √ | √ | √ | √ |
| Renew TLS certificate | √ | √ | √ | √ |
| Online user count | √ | √ | √ | √ |
| Online user limit | √ | √ | √ | √ |
| Audit rules | √ | √ | √ | √ |
| Node port speed limit | √ | √ | √ | √ |
| Per-user speed limit | √ | √ | √ | √ |
| Custom DNS | √ | √ | √ | √ |

## Panels

Set `PanelType` to the name in this table.

| Panel | VMess | VLESS | Trojan | Shadowsocks |
| --- | --- | --- | --- | --- |
| SSpanel (sspanel-uim) | √ | √ | √ | √ (single-port multi-user and V2Ray-Plugin) |
| NewV2board | √ | √ | √ | √ |
| [PMPanel](https://github.com/ByteInternetHK/PMPanel) | √ | √ | √ | √ |
| [ProxyPanel](https://github.com/ProxyPanel/ProxyPanel) | √ | √ | √ | √ |
| [WHMCS (V2RaySocks)](https://v2raysocks.doxtex.com/) | √ | √ | √ | √ |
| [GoV2Panel](https://github.com/pingProMax/gov2panel) | √ | √ | √ | √ |
| [BunPanel](https://github.com/pennyMorant/bunpanel-release) | √ | √ | √ | √ |

## Install

### One-step install

```bash
wget -N https://raw.githubusercontent.com/Vergelab/xrayr-release/master/install.sh && bash install.sh
```

### Manual install

Download the archive for your platform from [Releases](https://github.com/Vergelab/xrayr-release/releases). The Linux amd64 archive is `XrayR-linux-64.zip`. It contains the `XrayR` binary, `config.yml`, `custom_inbound.json`, `custom_outbound.json`, `dns.json`, `route.json`, `rulelist`, `geoip.dat`, `geosite.dat`, `LICENSE`, and `README.md`.

```bash
unzip XrayR-linux-64.zip -d /usr/local/XrayR
cd /usr/local/XrayR
# edit config.yml, then start
./XrayR
```

### Docker

The image `ghcr.io/vergelab/xrayr` is published when a release is published. Mount the config at `/etc/XrayR/config.yml`:

```bash
docker pull ghcr.io/vergelab/xrayr
docker run -d --name xrayr --network host \
  -v /etc/XrayR:/etc/XrayR \
  ghcr.io/vergelab/xrayr
```

## Configuration

The sample config is [`release/config/config.yml.example`](release/config/config.yml.example). DNS, routing, inbound, and outbound fields follow the Xray core config format. Comments in the sample point at those fields.

## Disclaimer

This program is for study and research. The maintainer does not guarantee availability and is not responsible for consequences of using this software.

## License

This project is licensed under the Mozilla Public License 2.0 (see [LICENSE](LICENSE)) and is derived from XrayR.
