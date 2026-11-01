package controller_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Vergelab/XrayR/api"
	"github.com/Vergelab/XrayR/common/mylego"
	. "github.com/Vergelab/XrayR/service/controller"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/transport/internet/reality"
)

func realityPrivateKey(t *testing.T) string {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes())
}

func realityNode(t *testing.T, dest string) (*Config, *api.NodeInfo) {
	t.Helper()
	nodeInfo := &api.NodeInfo{
		NodeType:          "Vless",
		NodeID:            7,
		Port:              443,
		TransportProtocol: "tcp",
		EnableTLS:         true,
		EnableREALITY:     true,
		VlessFlow:         "xtls-rprx-vision",
		REALITYConfig: &api.REALITYConfig{
			Dest:        dest,
			ServerNames: []string{"www.example.com"},
			PrivateKey:  realityPrivateKey(t),
			ShortIds:    []string{"0123456789abcdef"},
		},
	}
	config := &Config{
		DisableLocalREALITYConfig: true,
		CertConfig:                &mylego.CertConfig{CertMode: "none"},
	}
	return config, nodeInfo
}

func realityDestOf(t *testing.T, cfg *core.InboundHandlerConfig) string {
	t.Helper()
	recv, err := cfg.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	stream := recv.(*proxyman.ReceiverConfig).GetStreamSettings()
	if stream == nil || len(stream.SecuritySettings) == 0 {
		t.Fatal("missing REALITY security settings")
	}
	sec, err := stream.SecuritySettings[0].GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	realityCfg, ok := sec.(*reality.Config)
	if !ok {
		t.Fatalf("security is %T, want REALITY", sec)
	}
	return realityCfg.Dest
}

func TestBuildREALITYBlankPort(t *testing.T) {
	config, nodeInfo := realityNode(t, "www.example.com:")
	built, err := InboundBuilder(config, nodeInfo, "reality")
	if err != nil {
		t.Fatal(err)
	}
	if got := realityDestOf(t, built); got != "www.example.com:443" {
		t.Fatalf("dest = %q, want www.example.com:443", got)
	}
}

func TestBuildREALITYNilLocalConfig(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("nil REALITYConfigs panicked: %v", recovered)
		}
	}()
	config, nodeInfo := realityNode(t, "www.example.com")
	if config.REALITYConfigs != nil {
		t.Fatal("test requires a nil local REALITY config")
	}
	built, err := InboundBuilder(config, nodeInfo, "reality")
	if err != nil {
		t.Fatal(err)
	}
	if got := realityDestOf(t, built); got != "www.example.com:443" {
		t.Fatalf("dest = %q, want www.example.com:443", got)
	}
}

func TestBuildREALITYKeepsExplicitPort(t *testing.T) {
	config, nodeInfo := realityNode(t, "www.example.com:8443")
	nodeInfo.REALITYConfig.ProxyProtocolVer = 1
	built, err := InboundBuilder(config, nodeInfo, "reality")
	if err != nil {
		t.Fatal(err)
	}
	if got := realityDestOf(t, built); got != "www.example.com:8443" {
		t.Fatalf("dest = %q", got)
	}
	recv, err := built.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	sec, err := recv.(*proxyman.ReceiverConfig).GetStreamSettings().SecuritySettings[0].GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if sec.(*reality.Config).Xver != 1 {
		t.Fatalf("xver = %d", sec.(*reality.Config).Xver)
	}
}

func TestShadowsocksCiphers(t *testing.T) {
	cert := &mylego.CertConfig{CertMode: "none"}
	config := &Config{CertConfig: cert}

	aes, err := InboundBuilder(config, &api.NodeInfo{
		NodeType:          "Shadowsocks",
		Port:              10001,
		TransportProtocol: "tcp",
		CypherMethod:      "AEAD_AES_256_GCM",
	}, "ss-aes")
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := aes.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	server, ok := proxy.(*shadowsocks.ServerConfig)
	if !ok || len(server.Users) != 1 {
		t.Fatalf("legacy server = %#v", proxy)
	}
	accountMsg, err := server.Users[0].Account.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if accountMsg.(*shadowsocks.Account).CipherType != shadowsocks.CipherType_AES_256_GCM {
		t.Fatalf("cipher = %v", accountMsg.(*shadowsocks.Account).CipherType)
	}

	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	ss2022, err := InboundBuilder(config, &api.NodeInfo{
		NodeType:          "Shadowsocks",
		Port:              10002,
		TransportProtocol: "tcp",
		CypherMethod:      "2022-blake3-aes-128-gcm",
		ServerKey:         key,
	}, "ss-2022")
	if err != nil {
		t.Fatal(err)
	}
	proxy, err = ss2022.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	multi, ok := proxy.(*shadowsocks_2022.MultiUserServerConfig)
	if !ok {
		t.Fatalf("2022 server = %T", proxy)
	}
	if multi.Method != "2022-blake3-aes-128-gcm" || multi.Key != key {
		t.Fatalf("2022 config method=%s key=%s", multi.Method, multi.Key)
	}

	for _, method := range []string{"none", "plain", ""} {
		_, err := InboundBuilder(config, &api.NodeInfo{
			NodeType:          "Shadowsocks",
			Port:              10003,
			TransportProtocol: "tcp",
			CypherMethod:      method,
		}, "ss-bad")
		if err == nil || !strings.Contains(err.Error(), "shadowsocks cipher") {
			t.Fatalf("method %q error = %v", method, err)
		}
	}
}

func TestMKCPRemovedHeader(t *testing.T) {
	config := &Config{CertConfig: &mylego.CertConfig{CertMode: "none"}}
	_, err := InboundBuilder(config, &api.NodeInfo{
		NodeType:          "Vless",
		Port:              10004,
		TransportProtocol: "mkcp",
		Header:            []byte(`{"type":"srtp"}`),
	}, "kcp")
	if err == nil || !strings.Contains(err.Error(), "srtp") || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("srtp error = %v", err)
	}

	built, err := InboundBuilder(config, &api.NodeInfo{
		NodeType:          "Vless",
		Port:              10005,
		TransportProtocol: "kcp",
		Header:            []byte(`{"type":"none"}`),
	}, "kcp-none")
	if err != nil {
		t.Fatal(err)
	}
	recv, err := built.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if recv.(*proxyman.ReceiverConfig).GetStreamSettings().GetProtocolName() != "mkcp" {
		t.Fatalf("protocol = %s", recv.(*proxyman.ReceiverConfig).GetStreamSettings().GetProtocolName())
	}
}
