// Package controller Package generate the InboundConfig used by add inbound
package controller

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	stdnet "net"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"

	"github.com/Vergelab/XrayR/api"
	"github.com/Vergelab/XrayR/common/mylego"
)

// InboundBuilder build Inbound config for different protocol
func InboundBuilder(config *Config, nodeInfo *api.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	inboundDetourConfig := &conf.InboundDetourConfig{}
	// Build Listen IP address
	if nodeInfo.NodeType == "Shadowsocks-Plugin" {
		// Shdowsocks listen in 127.0.0.1 for safety
		inboundDetourConfig.ListenOn = &conf.Address{Address: net.ParseAddress("127.0.0.1")}
	} else if config.ListenIP != "" {
		ipAddress := net.ParseAddress(config.ListenIP)
		inboundDetourConfig.ListenOn = &conf.Address{Address: ipAddress}
	}

	// Build Port
	portList := &conf.PortList{
		Range: []conf.PortRange{{From: nodeInfo.Port, To: nodeInfo.Port}},
	}
	inboundDetourConfig.PortList = portList
	// Build Tag
	inboundDetourConfig.Tag = tag
	// SniffingConfig
	sniffingConfig := &conf.SniffingConfig{
		Enabled:      true,
		DestOverride: conf.StringList{"http", "tls", "quic", "fakedns"},
	}
	if config.DisableSniffing {
		sniffingConfig.Enabled = false
	}
	inboundDetourConfig.SniffingConfig = sniffingConfig

	var (
		protocol      string
		streamSetting *conf.StreamConfig
		setting       json.RawMessage
	)

	var proxySetting any
	// Build Protocol and Protocol setting
	switch nodeInfo.NodeType {
	case "V2ray", "Vmess", "Vless":
		if (nodeInfo.NodeType == "V2ray" && nodeInfo.EnableVless) || nodeInfo.NodeType == "Vless" {
			protocol = "vless"
			// Enable fallback
			if config.EnableFallback {
				fallbackConfigs, err := buildVlessFallbacks(config.FallBackConfigs)
				if err == nil {
					proxySetting = &conf.VLessInboundConfig{
						Decryption: "none",
						Fallbacks:  fallbackConfigs,
					}
				} else {
					return nil, err
				}
			} else {
				proxySetting = &conf.VLessInboundConfig{
					Decryption: "none",
				}
			}
		} else {
			protocol = "vmess"
			proxySetting = &conf.VMessInboundConfig{}
		}
	case "Trojan":
		protocol = "trojan"
		// Enable fallback
		if config.EnableFallback {
			fallbackConfigs, err := buildTrojanFallbacks(config.FallBackConfigs)
			if err == nil {
				proxySetting = &conf.TrojanServerConfig{
					Fallbacks: fallbackConfigs,
				}
			} else {
				return nil, err
			}
		} else {
			proxySetting = &conf.TrojanServerConfig{}
		}
	case "Shadowsocks", "Shadowsocks-Plugin":
		protocol = "shadowsocks"
		cipher, ss2022, err := classifyShadowsocksMethod(nodeInfo.CypherMethod)
		if err != nil {
			return nil, err
		}
		if config.DisableIVCheck {
			log.Warn("DisableIVCheck has no effect: xray-core v26 removed Shadowsocks IV replay protection")
		}

		proxySetting = &conf.ShadowsocksServerConfig{
			Cipher:   cipher,
			Password: nodeInfo.ServerKey, // shadowsocks2022 shareKey
		}

		proxySetting, _ := proxySetting.(*conf.ShadowsocksServerConfig)
		// Classic shadowsocks needs a server password even though each user brings their own.
		// Shadowsocks 2022 multi-user uses the panel server key plus per-user PSKs.
		if ss2022 {
			method, methodErr := shadowsocks_2022.GetCipherMethod(cipher)
			if methodErr != nil {
				return nil, fmt.Errorf("shadowsocks 2022 cipher %s: %w", cipher, methodErr)
			}
			if _, keyErr := shadowsocks_2022.ParseKey(nodeInfo.ServerKey, method.KeySaltLength); keyErr != nil {
				return nil, fmt.Errorf("shadowsocks 2022 server key for %s is invalid: %w", cipher, keyErr)
			}
			placeholder := make([]byte, method.KeySaltLength)
			if _, randErr := rand.Read(placeholder); randErr != nil {
				return nil, fmt.Errorf("shadowsocks 2022 placeholder key: %w", randErr)
			}
			proxySetting.Users = append(proxySetting.Users, &conf.ShadowsocksUserConfig{
				Password: base64.StdEncoding.EncodeToString(placeholder),
			})
		} else {
			b := make([]byte, 32)
			if _, randErr := rand.Read(b); randErr != nil {
				return nil, fmt.Errorf("shadowsocks password: %w", randErr)
			}
			proxySetting.Password = hex.EncodeToString(b)
		}

		proxySetting.NetworkList = &conf.NetworkList{"tcp", "udp"}

	case "dokodemo-door":
		protocol = "dokodemo-door"
		proxySetting = struct {
			Host        string   `json:"address"`
			NetworkList []string `json:"network"`
		}{
			Host:        "v1.mux.cool",
			NetworkList: []string{"tcp", "udp"},
		}
	default:
		return nil, fmt.Errorf("unsupported node type: %s, Only support: V2ray, Trojan, Shadowsocks, and Shadowsocks-Plugin", nodeInfo.NodeType)
	}

	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config failed: %s", nodeInfo.NodeType, err)
	}
	inboundDetourConfig.Protocol = protocol
	inboundDetourConfig.Settings = &setting

	// Build streamSettings
	streamSetting = new(conf.StreamConfig)
	transportProtocol := conf.TransportProtocol(nodeInfo.TransportProtocol)
	networkType, err := transportProtocol.Build()
	if err != nil {
		return nil, fmt.Errorf("convert TransportProtocol failed: %s", err)
	}

	if err := ValidateTransportHeader(networkType, nodeInfo.Header); err != nil {
		return nil, err
	}

	switch networkType {
	case "tcp":
		tcpSetting := &conf.TCPConfig{
			AcceptProxyProtocol: config.EnableProxyProtocol,
			HeaderConfig:        nodeInfo.Header,
		}
		streamSetting.TCPSettings = tcpSetting
	case "websocket":
		headers := make(map[string]string)
		headers["Host"] = nodeInfo.Host
		wsSettings := &conf.WebSocketConfig{
			AcceptProxyProtocol: config.EnableProxyProtocol,
			Host:                nodeInfo.Host,
			Path:                nodeInfo.Path,
			Headers:             headers,
		}
		streamSetting.WSSettings = wsSettings
	case "grpc":
		grpcSettings := &conf.GRPCConfig{
			ServiceName: nodeInfo.ServiceName,
			Authority:   nodeInfo.Authority,
		}
		streamSetting.GRPCSettings = grpcSettings
	case "httpupgrade":
		httpupgradeSettings := &conf.HttpUpgradeConfig{
			Headers:             nodeInfo.Headers,
			Path:                nodeInfo.Path,
			Host:                nodeInfo.Host,
			AcceptProxyProtocol: nodeInfo.AcceptProxyProtocol,
		}
		streamSetting.HTTPUPGRADESettings = httpupgradeSettings
	case "splithttp", "xhttp":
		splithttpSetting := &conf.SplitHTTPConfig{
			Path: nodeInfo.Path,
			Host: nodeInfo.Host,
		}
		streamSetting.SplitHTTPSettings = splithttpSetting
	case "mkcp":
		// Header camouflage is gone. ValidateTransportHeader already rejected
		// anything other than none; leave kcpSettings.header unset.
		streamSetting.KCPSettings = &conf.KCPConfig{}
	}
	streamSetting.Network = &transportProtocol

	// Build TLS and REALITY settings.
	// allowInsecure is rejected by xray-core v26; this builder never sets it.
	//
	// xray-core v26.10.31 reality (83f6217, from XTLS/REALITY 8cdf7bf) rejects
	// a ClientHello that does not offer X25519MLKEM768 and forwards it to the
	// decoy. With REALITYAllowNonPQClients false, only fingerprints that send
	// that hybrid group authenticate: chrome, firefox, and safari on Xray-core.
	// ios, edge, and qq do not. mihomo's default hello and sing-box strip the
	// hybrid group, so they do not connect either. android and 360 have no
	// TLS 1.3 key share and fail in both modes.
	//
	// The top-level REALITYAllowNonPQClients key defaults to true and is applied
	// process-wide (xray-core's REALITY protobuf has no field for it). X25519-only hellos
	// then authenticate with that share, so chrome, firefox, safari, ios,
	// edge, and qq connect. A client that still sends X25519MLKEM768 keeps
	// that group for the TLS handshake. mldsa65Seed stays optional.
	var isREALITY bool
	if config.DisableLocalREALITYConfig {
		if nodeInfo.REALITYConfig != nil && nodeInfo.EnableREALITY {
			isREALITY = true
			streamSetting.Security = "reality"

			r := nodeInfo.REALITYConfig
			dest, err := marshalRealityDest(r.Dest)
			if err != nil {
				return nil, err
			}
			show := false
			if config.REALITYConfigs != nil {
				show = config.REALITYConfigs.Show
			}
			streamSetting.REALITYSettings = &conf.REALITYConfig{
				Show:         show,
				Dest:         dest,
				Xver:         r.ProxyProtocolVer,
				ServerNames:  r.ServerNames,
				PrivateKey:   r.PrivateKey,
				MinClientVer: r.MinClientVer,
				MaxClientVer: r.MaxClientVer,
				MaxTimeDiff:  r.MaxTimeDiff,
				ShortIds:     r.ShortIds,
				Mldsa65Seed:  r.Mldsa65Seed,
			}
		}
	} else if config.EnableREALITY && config.REALITYConfigs != nil {
		isREALITY = true
		dest, err := marshalRealityDest(config.REALITYConfigs.Dest)
		if err != nil {
			return nil, err
		}
		streamSetting.Security = "reality"
		var privateKey string
		shortIDs := append([]string{}, config.REALITYConfigs.ShortIds...)
		mldsaSeed := config.REALITYConfigs.Mldsa65Seed
		if nodeInfo.REALITYConfig != nil {
			if nodeInfo.REALITYConfig.PrivateKey != "" {
				privateKey = nodeInfo.REALITYConfig.PrivateKey
			}
			shortIDs = append(shortIDs, nodeInfo.REALITYConfig.ShortIds...)
			if nodeInfo.REALITYConfig.Mldsa65Seed != "" {
				mldsaSeed = nodeInfo.REALITYConfig.Mldsa65Seed
			}
		} else {
			privateKey = config.REALITYConfigs.PrivateKey
		}
		streamSetting.REALITYSettings = &conf.REALITYConfig{
			Show:         config.REALITYConfigs.Show,
			Dest:         dest,
			Xver:         config.REALITYConfigs.ProxyProtocolVer,
			ServerNames:  config.REALITYConfigs.ServerNames,
			PrivateKey:   privateKey,
			MinClientVer: config.REALITYConfigs.MinClientVer,
			MaxClientVer: config.REALITYConfigs.MaxClientVer,
			MaxTimeDiff:  config.REALITYConfigs.MaxTimeDiff,
			ShortIds:     shortIDs,
			Mldsa65Seed:  mldsaSeed,
		}
	}

	// The panel said REALITY (tls=2). Do not fall through to TLS or to a
	// plaintext listener when the REALITY settings were not applied.
	if nodeInfo.EnableREALITY && !isREALITY {
		return nil, fmt.Errorf("panel enabled REALITY (tls=2) but REALITY was not applied. Set DisableLocalREALITYConfig: true and keep a REALITYConfigs block so the panel key is used, or set EnableREALITY: true with a complete local REALITYConfigs. Refusing to listen with TLS or without security")
	}

	if !isREALITY && nodeInfo.EnableTLS && config.CertConfig != nil && config.CertConfig.CertMode != "none" && config.CertConfig.CertMode != "" {
		streamSetting.Security = "tls"
		certFile, keyFile, err := getCertFile(config.CertConfig)
		if err != nil {
			return nil, err
		}
		tlsSettings := &conf.TLSConfig{
			RejectUnknownSNI: config.CertConfig.RejectUnknownSni,
		}
		tlsSettings.Certs = append(tlsSettings.Certs, &conf.TLSCertConfig{CertFile: certFile, KeyFile: keyFile, OcspStapling: 3600})
		streamSetting.TLSSettings = tlsSettings
	}

	// Support ProxyProtocol for any transport protocol
	if networkType != "tcp" && networkType != "ws" && config.EnableProxyProtocol {
		sockoptConfig := &conf.SocketConfig{
			AcceptProxyProtocol: config.EnableProxyProtocol,
		}
		streamSetting.SocketSettings = sockoptConfig
	}
	inboundDetourConfig.StreamSetting = streamSetting

	return inboundDetourConfig.Build()
}

func getCertFile(certConfig *mylego.CertConfig) (certFile string, keyFile string, err error) {
	switch certConfig.CertMode {
	case "file":
		if certConfig.CertFile == "" || certConfig.KeyFile == "" {
			return "", "", fmt.Errorf("cert file path or key file path not exist")
		}
		return certConfig.CertFile, certConfig.KeyFile, nil
	case "dns":
		lego, err := mylego.New(certConfig)
		if err != nil {
			return "", "", err
		}
		certPath, keyPath, err := lego.DNSCert()
		if err != nil {
			return "", "", err
		}
		return certPath, keyPath, err
	case "http", "tls":
		lego, err := mylego.New(certConfig)
		if err != nil {
			return "", "", err
		}
		certPath, keyPath, err := lego.HTTPCert()
		if err != nil {
			return "", "", err
		}
		return certPath, keyPath, err
	default:
		return "", "", fmt.Errorf("unsupported certmode: %s", certConfig.CertMode)
	}
}

func buildVlessFallbacks(fallbackConfigs []*FallBackConfig) ([]*conf.VLessInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}

	vlessFallBacks := make([]*conf.VLessInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {

		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback failed")
		}

		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config failed: %s", dest, err)
		}
		vlessFallBacks[i] = &conf.VLessInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return vlessFallBacks, nil
}

func buildTrojanFallbacks(fallbackConfigs []*FallBackConfig) ([]*conf.TrojanInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}

	trojanFallBacks := make([]*conf.TrojanInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {

		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback failed")
		}

		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config failed: %s", dest, err)
		}
		trojanFallBacks[i] = &conf.TrojanInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return trojanFallBacks, nil
}

// normalizeRealityDest turns a panel dest into host:port. A blank port,
// including the "sni:" form produced when server_port is an empty string,
// becomes 443. A dest that already has a port is kept.
func normalizeRealityDest(dest string) (string, error) {
	dest = strings.TrimSpace(dest)
	if dest == "" {
		return "", fmt.Errorf("REALITY dest is empty")
	}
	host, port, err := stdnet.SplitHostPort(dest)
	if err != nil {
		if strings.Contains(dest, " ") {
			return "", fmt.Errorf("REALITY dest %q is invalid", dest)
		}
		return stdnet.JoinHostPort(dest, "443"), nil
	}
	if port == "" {
		if host == "" {
			return "", fmt.Errorf("REALITY dest %q is invalid", dest)
		}
		dest = stdnet.JoinHostPort(host, "443")
	} else if host == "" {
		return "", fmt.Errorf("REALITY dest %q is invalid", dest)
	}
	return rejectEmptyRealityPort(dest)
}

// rejectEmptyRealityPort fails the build when dest still has no port.
// Callers default a blank port to 443 before this check.
func rejectEmptyRealityPort(dest string) (string, error) {
	host, port, err := stdnet.SplitHostPort(dest)
	if err != nil || host == "" || port == "" {
		return "", fmt.Errorf("REALITY dest %q has an empty port", dest)
	}
	return dest, nil
}

func marshalRealityDest(dest string) (json.RawMessage, error) {
	normalized, err := normalizeRealityDest(dest)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal REALITY dest %s: %w", normalized, err)
	}
	return raw, nil
}

// removedMKCPHeaders are the mKCP camouflage types xray-core v26 dropped.
// The KCP config builder ignores header entirely, so accepting one would
// start a plain mKCP listener that those clients cannot speak.
var removedMKCPHeaders = map[string]struct{}{
	"srtp":         {},
	"utp":          {},
	"wechat":       {},
	"wechat-video": {},
	"dtls":         {},
	"tls":          {},
	"wireguard":    {},
	"dns":          {},
}

// ValidateTransportHeader rejects a removed mKCP header instead of letting
// the node come up as header type none. "none" (and an empty header) is the
// only remaining mKCP header. TCP "http" obfuscation is unchanged.
func ValidateTransportHeader(network string, header json.RawMessage) error {
	headerType, err := transportHeaderType(header)
	if err != nil {
		if isKCPNetwork(network) {
			return fmt.Errorf("mKCP header config is invalid JSON: %w", err)
		}
		return nil
	}
	if headerType == "" || headerType == "none" || headerType == "noop" {
		return nil
	}
	if isKCPNetwork(network) || removedMKCPHeader(headerType) {
		return fmt.Errorf("mKCP header type %q is not supported on xray-core v26: camouflage headers were removed and are no longer applied (srtp, utp, wechat, wechat-video, dtls, tls, wireguard, dns). Set the node header type to none. Refusing to start so clients are not left talking to a plain mKCP listener", headerType)
	}
	return nil
}

func isKCPNetwork(network string) bool {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "kcp", "mkcp":
		return true
	default:
		return false
	}
}

func removedMKCPHeader(headerType string) bool {
	_, ok := removedMKCPHeaders[headerType]
	return ok
}

func transportHeaderType(header json.RawMessage) (string, error) {
	trimmed := strings.TrimSpace(string(header))
	if trimmed == "" || trimmed == "null" {
		return "", nil
	}
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(probe.Type)), nil
}
