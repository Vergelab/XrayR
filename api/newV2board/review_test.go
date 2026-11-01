package newV2board

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Vergelab/XrayR/api"
)

func TestServerPortAndXverAcceptStringOrNumber(t *testing.T) {
	raw := []byte(`{
		"server_port": "2443",
		"network": "tcp",
		"tls": 2,
		"tls_settings": {
			"server_port": 8443,
			"server_name": "www.example.com",
			"private_key": "priv",
			"short_id": "ab",
			"xver": "2"
		}
	}`)
	var server serverConfig
	if err := json.Unmarshal(raw, &server); err != nil {
		t.Fatal(err)
	}
	if server.ServerPort != 2443 {
		t.Fatalf("listen port = %d", server.ServerPort)
	}
	if string(server.TlsSettings.ServerPort) != "8443" || server.TlsSettings.Xver != 2 {
		t.Fatalf("tls port=%s xver=%d", server.TlsSettings.ServerPort, server.TlsSettings.Xver)
	}
	client := &APIClient{NodeType: "Vless", EnableVless: true, VlessFlow: "xtls-rprx-vision"}
	info, err := client.parseV2rayNodeResponse(&server)
	if err != nil {
		t.Fatal(err)
	}
	if info.Port != 2443 || info.REALITYConfig.Dest != "www.example.com:8443" {
		t.Fatalf("port=%d dest=%s", info.Port, info.REALITYConfig.Dest)
	}
	if info.REALITYConfig.ProxyProtocolVer != 2 {
		t.Fatalf("xver = %d", info.REALITYConfig.ProxyProtocolVer)
	}
}

func TestBlankServerPortDefaults443(t *testing.T) {
	client := &APIClient{NodeType: "Vless", EnableVless: true}
	info, err := client.parseV2rayNodeResponse(&serverConfig{
		ServerPort: 443,
		v2ray: v2ray{
			Network: "tcp",
			Tls:     2,
			TlsSettings: struct {
				ServerPort  FlexString `json:"server_port"`
				Dest        string     `json:"dest"`
				Xver        FlexUint64 `json:"xver"`
				Sni         string     `json:"server_name"`
				PrivateKey  string     `json:"private_key"`
				ShortId     string     `json:"short_id"`
				Mldsa65Seed string     `json:"mldsa65Seed"`
				Mldsa65     string     `json:"mldsa65"`
			}{ServerPort: "", Sni: "www.example.com", PrivateKey: "priv"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.REALITYConfig.Dest != "www.example.com:443" {
		t.Fatalf("dest = %s", info.REALITYConfig.Dest)
	}
}

func TestUnmarshalErrorIsReturnedAndRedacted(t *testing.T) {
	body := []byte(`{"server_port":443,"tls":"nope","tls_settings":{"private_key":"super-secret","server_name":"www.example.com"}}`)
	var server serverConfig
	err := json.Unmarshal(body, &server)
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
	redacted := redactPanelBody(body)
	if strings.Contains(redacted, "super-secret") {
		t.Fatalf("private key leaked: %s", redacted)
	}
	if !strings.Contains(redacted, "[redacted]") {
		t.Fatalf("redacted body = %s", redacted)
	}
}

func TestUsersNullAndEmptyRemoveEveryone(t *testing.T) {
	client := &APIClient{NodeType: "Vless"}
	for _, raw := range []string{"null", "[]", ""} {
		list, err := client.usersFromJSON([]byte(raw))
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if list == nil || len(*list) != 0 {
			t.Fatalf("%q list = %#v", raw, list)
		}
	}
}

func TestDeviceLimitReadFromUserPayload(t *testing.T) {
	client := &APIClient{NodeType: "Vless"}
	list, err := client.usersFromJSON([]byte(`[{"id":3,"uuid":"abc","speed_limit":1,"device_limit":4}]`))
	if err != nil {
		t.Fatal(err)
	}
	if (*list)[0].DeviceLimit != 4 || (*list)[0].UID != 3 {
		t.Fatalf("user = %#v", (*list)[0])
	}
	missing, err := client.usersFromJSON([]byte(`[{"id":3,"uuid":"abc","speed_limit":1}]`))
	if err != nil {
		t.Fatal(err)
	}
	if (*missing)[0].DeviceLimit != 0 {
		t.Fatalf("missing device_limit = %d", (*missing)[0].DeviceLimit)
	}
	client.DeviceLimit = 9
	over, err := client.usersFromJSON([]byte(`[{"id":3,"uuid":"abc","speed_limit":0,"device_limit":4}]`))
	if err != nil {
		t.Fatal(err)
	}
	if (*over)[0].DeviceLimit != 9 {
		t.Fatalf("local override = %d", (*over)[0].DeviceLimit)
	}
}

func TestEmptyPanelFlowUsesLocal(t *testing.T) {
	client := &APIClient{NodeType: "Vless", EnableVless: true, NodeID: 7, VlessFlow: "xtls-rprx-vision"}
	info, err := client.parseV2rayNodeResponse(&serverConfig{
		ServerPort: 443,
		v2ray: v2ray{
			Network:   "tcp",
			VlessFlow: "",
			Tls:       2,
			TlsSettings: struct {
				ServerPort  FlexString `json:"server_port"`
				Dest        string     `json:"dest"`
				Xver        FlexUint64 `json:"xver"`
				Sni         string     `json:"server_name"`
				PrivateKey  string     `json:"private_key"`
				ShortId     string     `json:"short_id"`
				Mldsa65Seed string     `json:"mldsa65Seed"`
				Mldsa65     string     `json:"mldsa65"`
			}{Sni: "www.example.com", PrivateKey: "priv"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.VlessFlow != "xtls-rprx-vision" {
		t.Fatalf("flow = %q", info.VlessFlow)
	}
	panel, err := client.parseV2rayNodeResponse(&serverConfig{
		ServerPort: 443,
		v2ray: v2ray{
			Network:   "tcp",
			VlessFlow: "xtls-rprx-vision-udp443",
			Tls:       0,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if panel.VlessFlow != "xtls-rprx-vision-udp443" {
		t.Fatalf("panel flow = %q", panel.VlessFlow)
	}
}

func TestBadRuleIsSkipped(t *testing.T) {
	client := &APIClient{LocalRuleList: []api.DetectRule{}}
	client.resp.Store(&serverConfig{Routes: []route{
		{Action: "block", Match: []string{"["}},
		{Action: "block", Match: []string{"evil\\.example"}},
	}})
	rules, err := client.GetNodeRule()
	if err != nil {
		t.Fatal(err)
	}
	if rules == nil || len(*rules) != 1 {
		t.Fatalf("rules = %#v", rules)
	}
}

func TestPanelBodyStatus(t *testing.T) {
	if err := panelBodyStatus([]byte(`{"status":"success","data":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := panelBodyStatus([]byte(`{"data":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := panelBodyStatus([]byte(`{"status":"fail"}`)); err == nil {
		t.Fatal("expected fail status")
	}
}

func TestPushHTTPStatusAndBody(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"status":"fail"}`))
			return
		}
		if calls == 2 {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"fail","message":"queued-only"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success","data":true}`))
	}))
	defer srv.Close()
	client := New(&api.Config{APIHost: srv.URL, Key: "tok", NodeID: 1, NodeType: "Vless", EnableVless: true})
	traffic := []api.UserTraffic{{UID: 1, Upload: 10, Download: 20}}
	if err := client.ReportUserTraffic(&traffic); err == nil {
		t.Fatal("http 502 should fail")
	}
	if err := client.ReportUserTraffic(&traffic); err == nil {
		t.Fatal("body status fail should fail")
	}
	if err := client.ReportUserTraffic(&traffic); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(srv.URL, "127.0.0.1") && !strings.Contains(srv.URL, "localhost") {
		t.Fatal(srv.URL)
	}
}

func TestAliveList404KeepsPreviousMap(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if strings.Contains(r.URL.Path, "alivelist") {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"users":[]}`))
	}))
	defer srv.Close()
	client := New(&api.Config{APIHost: srv.URL, Key: "tok", NodeID: 1, NodeType: "Vless"})
	client.aliveMu.Lock()
	client.AliveMap = &AliveMap{Alive: map[int]int{7: 2}}
	client.aliveMu.Unlock()
	got, err := client.GetUserAlive()
	if err != nil {
		t.Fatal(err)
	}
	if got[7] != 2 {
		t.Fatalf("alive wiped: %#v", got)
	}
	if _, err := client.GetUserAlive(); err != nil {
		t.Fatal(err)
	}
	if hits < 2 {
		t.Fatalf("hits = %d", hits)
	}
}

func TestAliveFailureDoesNotClearMap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`nope`))
	}))
	defer srv.Close()
	client := New(&api.Config{APIHost: srv.URL, Key: "tok", NodeID: 1, NodeType: "Vless"})
	client.aliveMu.Lock()
	client.AliveMap = &AliveMap{Alive: map[int]int{1: 3}}
	client.aliveMu.Unlock()
	got, err := client.GetUserAlive()
	if err == nil {
		t.Fatal("expected error")
	}
	if got[1] != 3 {
		t.Fatalf("alive = %#v", got)
	}
}

func TestPushIntervalFromConfig(t *testing.T) {
	raw := []byte(`{"server_port":1,"network":"tcp","tls":0,"base_config":{"push_interval":15,"pull_interval":60}}`)
	var server serverConfig
	if err := json.Unmarshal(raw, &server); err != nil {
		t.Fatal(err)
	}
	if server.BaseConfig.PushInterval != 15 {
		t.Fatalf("push_interval = %d", server.BaseConfig.PushInterval)
	}
	client := &APIClient{}
	client.pushInterval.Store(int64(server.BaseConfig.PushInterval))
	if client.PushInterval() != 15 {
		t.Fatalf("PushInterval = %d", client.PushInterval())
	}
}
