# Vendored github.com/xtls/reality

Upstream: https://github.com/xtls/reality

Commit: `4bb46b2afd8b` (2026-11-08), the version required by
`github.com/xtls/xray-core` v26.11.9.
Pseudo-version: `v0.0.0-20261108101329-4bb46b2afd8b`.

This is two commits ahead of `83f621788ca8` (the copy used with
xray-core v26.10.31). The upstream additions are only in
`record_detect.go` (XTLS/REALITY #42 and #43): a 10-second deadline on
dest probe handshakes, and `InsecureSkipVerify` when the probe SNI is
empty. The Server() key-share rejection from `8cdf7bf` is unchanged.

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
still present in `4bb46b2afd8b` as:

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
