# XrayR

Xray backend maintained by Vergelab. One process can serve several panels and nodes. The command and binary name stay `XrayR`, so existing install paths, systemd units, and scripts keep working.

Current version: **0.3**

- Source: https://github.com/Vergelab/XrayR
- Install scripts and releases: https://github.com/Vergelab/xrayr-release
- Container image: `ghcr.io/vergelab/xrayr`
- 中文: [README.md](README.md)

`XrayR version` prints `XrayR 0.3 (Vergelab)`.

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
| Server status report | √ | √ | √ | √ (NewV2board does not upload it; the call returns success) |
| Issue TLS certificate | √ | √ | √ | √ |
| Renew TLS certificate | √ | √ | √ | √ |
| Online user count | √ | √ | √ | √ |
| Online user limit | √ | √ | √ | √ (see device-limit note below) |
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

## Routing

The shipped `route.json` sends all TCP/UDP to `direct`. `custom_outbound.json` is a freedom direct exit and has no WARP key. The previous samples, which included a sample WARP key, are [`route.json.example`](release/config/route.json.example) and [`custom_outbound.json.example`](release/config/custom_outbound.json.example). Do not run those as production config.

## NewV2board / Xboard

- Server status is not reported. `ReportNodeStatus` returns success. Xboard 0.1.1 has no matching write.
- Device limit counts distinct local source IPs for that user on this node, and also the panel alive count when the panel provides one. Xboard 0.1.1-dev users have no `device_limit` field and no `alivelist` (HTTP 404, logged once). Set `DeviceLimit` in the node config to enforce it. If the user payload includes `device_limit` and the local `DeviceLimit` is 0, the payload value is used. A failed alivelist poll keeps the last good map.
- Each `RuleListPath` line is an unanchored regular expression (`.` matches any character) and is a block rule. A line that does not compile is skipped and logged.
- An empty panel `flow` uses local `ApiConfig.VlessFlow`. The NewV2board example sets `xtls-rprx-vision` and `DisableLocalREALITYConfig: true`. If the panel says REALITY and it was not applied, the node build fails instead of falling back to TLS or plaintext.
- The API token stays a query parameter. Xboard 0.1.1-dev validates `token` with Laravel `$request->validate`, which reads the query string and body, not a header.
- `ControllerConfig.REALITYAllowNonPQClients` defaults to true, including when the key is omitted. REALITY in xray-core v26.10.31 forwards a ClientHello that lacks `X25519MLKEM768` to the decoy, so edge, ios, qq, mihomo's default hello, and sing-box cannot connect; only chrome, firefox, and safari can. With the option on, an X25519-only hello is authenticated with that X25519 share. A client that still sends `X25519MLKEM768` keeps that hybrid group for the TLS handshake. The trade-off is that a non-PQ hello with a valid shortId completes REALITY instead of falling through to the decoy, so an active probe can tell this node apart from upstream Xray. Set it to false to match upstream. android and 360 work in neither mode: they have no TLS 1.3 key share. The value is process-wide, because xray-core's REALITY protobuf has no per-inbound field; if nodes in one process disagree, the first node's value is used and a warning is logged. Hot reload applies the new value before the new listeners start.

## Disclaimer

This program is for study and research. The maintainer does not guarantee availability and is not responsible for consequences of using this software.

## License

This project is licensed under the Mozilla Public License 2.0 (see [LICENSE](LICENSE)) and is derived from XrayR.
