# Vendored github.com/xtls/reality

Upstream: https://github.com/xtls/reality

Commit: `83f621788ca8` (2026-10-14), the version required by
`github.com/xtls/xray-core` v26.10.31
(`v1.260327.1-0.20261031132019-a4a3dff5b20c`).
Pseudo-version: `v0.0.0-20261014101318-83f621788ca8`.

This directory is that module plus one behavior change. XrayR's `go.mod`
selects it with:

```
replace github.com/xtls/reality => ./third_party/reality
```

Licenses are the upstream ones and are not changed:

- `LICENSE` — Mozilla Public License 2.0, Copyright (c) 2023 RPRX (REALITY)
- `LICENSE-Go` — BSD-style license for the forked Go `crypto/tls` sources

## The change

`tls.go` calls `selectREALITYPeerPub` (`peerpub.go`) instead of the inline
check from XTLS/REALITY commit `8cdf7bf` ("reject outdated/strange Client
Hello that doesn't have X25519MLKEM768 before optional X25519"), which is
present in `83f621788ca8` as:

```go
if peerPub2 == nil {
    break
}
```

That `break` forwards the connection to the decoy. Fingerprints that send
only X25519 (edge, ios, qq, sing-box, mihomo's default hello) never complete
REALITY. android and 360 still have no TLS 1.3 key share and are unchanged.

`Config.AllowNonPQClients` and `SetAllowNonPQClients` (`nonpq.go`) accept
those hellos. Authentication uses the standalone X25519 key share. A client
that sends `X25519MLKEM768` is handled as before: auth still prefers a
standalone X25519 share when both are present, and the TLS handshake still
uses the group chosen by `dest`. When the client offered the hybrid group
and `dest` negotiates it, the negotiated group stays `X25519MLKEM768`.

xray-core copies a fixed protobuf (`transport/internet/reality.Config`) into
`reality.Config` inside `GetREALITYConfig`. That protobuf has no extension
field, so XrayR cannot set `AllowNonPQClients` per inbound without forking
xray-core. XrayR calls `SetAllowNonPQClients` from the top-level `REALITYAllowNonPQClients` key in `config.yml` at startup
and again on hot reload, before listeners accept. Callers that build
`reality.Config` themselves can still set the struct field; it is OR-ed
with the process flag.
