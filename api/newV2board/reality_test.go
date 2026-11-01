package newV2board

import (
	"encoding/json"
	"testing"
)

func TestParsePanelREALITY(t *testing.T) {
	raw := []byte(`{
		"server_port": 443,
		"network": "tcp",
		"flow": "xtls-rprx-vision",
		"tls": 2,
		"tls_settings": {
			"server_port": "",
			"server_name": "www.example.com",
			"public_key": "client-side-only",
			"private_key": "priv",
			"short_id": "abcd"
		}
	}`)
	var server serverConfig
	if err := json.Unmarshal(raw, &server); err != nil {
		t.Fatal(err)
	}
	client := &APIClient{NodeType: "Vless", NodeID: 1, EnableVless: true}
	info, err := client.parseV2rayNodeResponse(&server)
	if err != nil {
		t.Fatal(err)
	}
	if !info.EnableTLS || !info.EnableREALITY {
		t.Fatalf("tls=%v reality=%v", info.EnableTLS, info.EnableREALITY)
	}
	if info.REALITYConfig == nil || info.REALITYConfig.Dest != "www.example.com:443" {
		t.Fatalf("dest = %#v", info.REALITYConfig)
	}
	if info.VlessFlow != "xtls-rprx-vision" || info.TransportProtocol != "tcp" {
		t.Fatalf("flow=%s network=%s", info.VlessFlow, info.TransportProtocol)
	}
	if info.REALITYConfig.ShortIds[0] != "abcd" || info.REALITYConfig.PrivateKey != "priv" {
		t.Fatalf("keys = %#v", info.REALITYConfig)
	}
}

func TestREALITYDestKeepsExistingPortAndIPv6(t *testing.T) {
	// A sibling adapter always concatenates dest + ":" + server_port. A dest
	// that already has a port then fails xray with: please fill in a valid
	// value for "target".
	cases := []struct {
		dest, serverPort, want string
	}{
		{dest: "www.example.com:443", serverPort: "8443", want: "www.example.com:443"},
		{dest: "www.example.com", serverPort: "8443", want: "www.example.com:8443"},
		{dest: "www.example.com", serverPort: "", want: "www.example.com:443"},
		{dest: "www.example.com:", serverPort: "8443", want: "www.example.com:8443"},
		{dest: "1.2.3.4:443", serverPort: "80", want: "1.2.3.4:443"},
		{dest: "[2001:db8::1]:8443", serverPort: "443", want: "[2001:db8::1]:8443"},
		{dest: "[2001:db8::1]", serverPort: "443", want: "[2001:db8::1]:443"},
		{dest: "2001:db8::1", serverPort: "8443", want: "[2001:db8::1]:8443"},
		{dest: "::1", serverPort: "", want: "[::1]:443"},
		{dest: "[::1]", serverPort: "9443", want: "[::1]:9443"},
		{dest: "[fe80::1%eth0]:443", serverPort: "80", want: "[fe80::1%eth0]:443"},
		{dest: "fe80::1%eth0", serverPort: "443", want: "[fe80::1%eth0]:443"},
	}
	for _, tc := range cases {
		got, err := realityDestFromPanel(tc.dest, tc.serverPort)
		if err != nil {
			t.Fatalf("dest %q port %q: %v", tc.dest, tc.serverPort, err)
		}
		if got != tc.want {
			t.Fatalf("dest %q port %q = %q, want %q", tc.dest, tc.serverPort, got, tc.want)
		}
	}

	raw := []byte(`{
		"server_port": 443,
		"network": "tcp",
		"tls": 2,
		"tls_settings": {
			"dest": "www.example.com:443",
			"server_port": "8443",
			"server_name": "www.example.com",
			"private_key": "priv",
			"short_id": "ab"
		}
	}`)
	var server serverConfig
	if err := json.Unmarshal(raw, &server); err != nil {
		t.Fatal(err)
	}
	info, err := (&APIClient{NodeType: "Vless", EnableVless: true}).parseV2rayNodeResponse(&server)
	if err != nil {
		t.Fatal(err)
	}
	if info.REALITYConfig.Dest != "www.example.com:443" {
		t.Fatalf("parsed dest = %s", info.REALITYConfig.Dest)
	}

	raw = []byte(`{
		"server_port": 443,
		"network": "tcp",
		"tls": 2,
		"tls_settings": {
			"dest": "[2001:db8::1]",
			"server_port": 8443,
			"server_name": "www.example.com",
			"private_key": "priv",
			"short_id": "ab"
		}
	}`)
	if err := json.Unmarshal(raw, &server); err != nil {
		t.Fatal(err)
	}
	info, err = (&APIClient{NodeType: "Vless", EnableVless: true}).parseV2rayNodeResponse(&server)
	if err != nil {
		t.Fatal(err)
	}
	if info.REALITYConfig.Dest != "[2001:db8::1]:8443" {
		t.Fatalf("parsed ipv6 dest = %s", info.REALITYConfig.Dest)
	}
}

func TestParsePanelREALITYOptionalDestAndXver(t *testing.T) {
	raw := []byte(`{
		"server_port": 2443,
		"network": "tcp",
		"tls": 2,
		"tls_settings": {
			"dest": "www.example.com:8443",
			"server_port": "443",
			"server_name": "www.example.com",
			"private_key": "priv",
			"short_id": "",
			"xver": 2
		}
	}`)
	var numbered serverConfig
	if err := json.Unmarshal(raw, &numbered); err != nil {
		t.Fatal(err)
	}
	if numbered.TlsSettings.Xver != 2 {
		t.Fatalf("numeric xver = %d", numbered.TlsSettings.Xver)
	}
	client := &APIClient{NodeType: "Vless", EnableVless: true}
	info, err := client.parseV2rayNodeResponse(&numbered)
	if err != nil {
		t.Fatal(err)
	}
	if info.REALITYConfig.Dest != "www.example.com:8443" || info.REALITYConfig.ProxyProtocolVer != 2 {
		t.Fatalf("dest=%s xver=%d", info.REALITYConfig.Dest, info.REALITYConfig.ProxyProtocolVer)
	}

	stringXver := []byte(`{"tls_settings":{"xver":"1","server_port":""}}`)
	var asString serverConfig
	if err := json.Unmarshal(stringXver, &asString); err != nil {
		t.Fatal(err)
	}
	if asString.TlsSettings.Xver != 1 {
		t.Fatalf("string xver = %d", asString.TlsSettings.Xver)
	}
}
