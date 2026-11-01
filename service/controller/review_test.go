package controller

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Vergelab/XrayR/api"
	"github.com/Vergelab/XrayR/app/mydispatcher"
	_ "github.com/Vergelab/XrayR/cmd/distro/all"
	"github.com/Vergelab/XrayR/common/mylego"
	"github.com/xtls/xray-core/app/proxyman"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

func TestOnlineUsersOverThreshold(t *testing.T) {
	online := []api.OnlineUser{{UID: 1, IP: "10.0.0.1"}, {UID: 2, IP: "10.0.0.2"}, {UID: 3, IP: "10.0.0.3"}}
	traffic := []api.UserTraffic{
		{UID: 1, Upload: 100, Download: 100},
		{UID: 2, Upload: 50, Download: 0},
	}
	got := onlineUsersOverThreshold(online, traffic, 0)
	if len(got) != 2 {
		t.Fatalf("got %#v", got)
	}
	quiet := onlineUsersOverThreshold(online, traffic, 1)
	if len(quiet) != 0 {
		t.Fatalf("threshold filtered %#v", quiet)
	}
}

func TestSnapshotCounterRestoresOnFailure(t *testing.T) {
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	counter, err := manager.GetOrRegisterCounter("user>>>t>>>traffic>>>uplink")
	if err != nil {
		t.Fatal(err)
	}
	counter.Add(100)
	counter.Add(5)
	snap := snapshotCounter(counter)
	if snap != 105 || counter.Value() != 0 {
		t.Fatalf("snap=%d value=%d", snap, counter.Value())
	}
	counter.Add(7)
	restoreCounter(counter, snap)
	if counter.Value() != 112 {
		t.Fatalf("restored value = %d, want 112", counter.Value())
	}
}

func TestEmptyUserListRemovesUser(t *testing.T) {
	oldUsers := []api.UserInfo{{UID: 1, Email: "a@b", UUID: "u"}}
	empty := []api.UserInfo{}
	deleted, added := compareUserList(&oldUsers, &empty)
	if len(added) != 0 || len(deleted) != 1 || deleted[0].UID != 1 {
		t.Fatalf("deleted=%#v added=%#v", deleted, added)
	}
}

func TestBuildREALITYNotApplied(t *testing.T) {
	_, err := InboundBuilder(&Config{
		EnableREALITY:             false,
		DisableLocalREALITYConfig: false,
		CertConfig:                &mylego.CertConfig{CertMode: "file", CertFile: "c", KeyFile: "k"},
	}, &api.NodeInfo{
		NodeType:          "Vless",
		Port:              443,
		TransportProtocol: "tcp",
		EnableTLS:         true,
		EnableREALITY:     true,
		REALITYConfig: &api.REALITYConfig{
			Dest:        "www.example.com:443",
			ServerNames: []string{"www.example.com"},
			PrivateKey:  "priv",
			ShortIds:    []string{"ab"},
		},
	}, "tag")
	if err == nil || !contains(err.Error(), "REALITY") {
		t.Fatalf("err = %v", err)
	}
}

func TestNilREALITYConfigDoesNotPanic(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("panic: %v", recovered)
		}
	}()
	key := testRealityKey(t)
	_, err := InboundBuilder(&Config{
		EnableREALITY: true,
		REALITYConfigs: &REALITYConfig{
			Dest:        "www.example.com:443",
			ServerNames: []string{"www.example.com"},
			PrivateKey:  key,
			ShortIds:    []string{"0123456789abcdef"},
		},
		CertConfig: &mylego.CertConfig{CertMode: "none"},
	}, &api.NodeInfo{
		NodeType:          "Vless",
		Port:              443,
		TransportProtocol: "tcp",
		EnableTLS:         true,
		EnableREALITY:     true,
		REALITYConfig:     nil,
	}, "tag")
	if err != nil {
		t.Fatal(err)
	}
}

func TestBadREALITYKeepsOldInbound(t *testing.T) {
	server := newTestCore(t)
	node := goodRealityNode(t, 19021)
	apiClient := &fakeAPI{node: node, users: usersOf(node)}
	c := New(server, apiClient, &Config{
		ListenIP:                  "127.0.0.1",
		SendIP:                    "0.0.0.0",
		UpdatePeriodic:            1,
		DisableLocalREALITYConfig: true,
		DisableGetRule:            true,
		CertConfig:                &mylego.CertConfig{CertMode: "none"},
		AutoSpeedLimitConfig:      &AutoSpeedLimitConfig{},
	}, "NewV2board")
	c.startAt = time.Now().Add(-time.Hour)
	c.nodeInfo = node
	c.Tag = fmt.Sprintf("%s_%s_%d", node.NodeType, c.config.ListenIP, node.Port)
	c.userList = apiClient.users
	if err := c.addNewTag(node); err != nil {
		t.Fatal(err)
	}
	if err := c.addNewUser(apiClient.users, node); err != nil {
		t.Fatal(err)
	}
	oldTag := c.Tag
	bad := *node
	bad.REALITYConfig = &api.REALITYConfig{
		Dest:        node.REALITYConfig.Dest,
		ServerNames: append([]string{}, node.REALITYConfig.ServerNames...),
		PrivateKey:  "",
		ShortIds:    append([]string{}, node.REALITYConfig.ShortIds...),
	}
	apiClient.node = &bad
	if err := c.nodeInfoMonitor(); err != nil {
		t.Fatal(err)
	}
	if c.nodeInfo.REALITYConfig.PrivateKey == "" {
		t.Fatal("failed config was recorded")
	}
	if _, err := c.ibm.GetHandler(context.Background(), oldTag); err != nil {
		t.Fatalf("old inbound gone: %v", err)
	}
}

func TestPortChangeRollsBackWhenAddFails(t *testing.T) {
	server := newTestCore(t)
	node := goodRealityNode(t, 19031)
	apiClient := &fakeAPI{node: node, users: usersOf(node)}
	c := New(server, apiClient, &Config{
		ListenIP:                  "127.0.0.1",
		SendIP:                    "0.0.0.0",
		UpdatePeriodic:            1,
		DisableLocalREALITYConfig: true,
		DisableGetRule:            true,
		CertConfig:                &mylego.CertConfig{CertMode: "none"},
		AutoSpeedLimitConfig:      &AutoSpeedLimitConfig{},
	}, "NewV2board")
	c.startAt = time.Now().Add(-time.Hour)
	c.nodeInfo = node
	c.Tag = fmt.Sprintf("%s_%s_%d", node.NodeType, c.config.ListenIP, node.Port)
	c.userList = apiClient.users
	if err := c.addNewTag(node); err != nil {
		t.Fatal(err)
	}
	oldTag := c.Tag
	ln, err := net.Listen("tcp", "127.0.0.1:19032")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	moved := *node
	moved.Port = 19032
	moved.REALITYConfig = node.REALITYConfig
	apiClient.node = &moved
	if err := c.nodeInfoMonitor(); err != nil {
		t.Fatal(err)
	}
	if c.nodeInfo.Port != 19031 {
		t.Fatalf("port recorded as %d", c.nodeInfo.Port)
	}
	if _, err := c.ibm.GetHandler(context.Background(), oldTag); err != nil {
		t.Fatalf("rolled-back inbound missing: %v", err)
	}
}

func newTestCore(t *testing.T) *core.Instance {
	t.Helper()
	logConfig := &conf.LogConfig{LogLevel: "warning"}
	policyConfig := &conf.PolicyConfig{Levels: map[uint32]*conf.Policy{0: {
		StatsUserUplink:   true,
		StatsUserDownlink: true,
	}}}
	policy, err := policyConfig.Build()
	if err != nil {
		t.Fatal(err)
	}
	dns, err := (&conf.DNSConfig{}).Build()
	if err != nil {
		t.Fatal(err)
	}
	router, err := (&conf.RouterConfig{}).Build()
	if err != nil {
		t.Fatal(err)
	}
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(logConfig.Build()),
			serial.ToTypedMessage(&mydispatcher.Config{}),
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(policy),
			serial.ToTypedMessage(dns),
			serial.ToTypedMessage(router),
		},
	}
	server, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return server
}

func goodRealityNode(t *testing.T, port uint32) *api.NodeInfo {
	t.Helper()
	return &api.NodeInfo{
		NodeType:          "Vless",
		NodeID:            1,
		Port:              port,
		TransportProtocol: "tcp",
		EnableTLS:         true,
		EnableVless:       true,
		EnableREALITY:     true,
		VlessFlow:         "xtls-rprx-vision",
		REALITYConfig: &api.REALITYConfig{
			Dest:        "www.example.com:443",
			ServerNames: []string{"www.example.com"},
			PrivateKey:  testRealityKey(t),
			ShortIds:    []string{"0123456789abcdef"},
		},
	}
}

func usersOf(node *api.NodeInfo) *[]api.UserInfo {
	users := []api.UserInfo{{
		UID:   1,
		UUID:  "b831381d-6324-4d53-ad4f-8cda48b30811",
		Email: "b831381d-6324-4d53-ad4f-8cda48b30811@v2board.user",
	}}
	return &users
}

func testRealityKey(t *testing.T) string {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes())
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (len(s) > 0 && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()))
}

type fakeAPI struct {
	node  *api.NodeInfo
	users *[]api.UserInfo
}

func (f *fakeAPI) GetNodeInfo() (*api.NodeInfo, error) {
	cp := *f.node
	return &cp, nil
}
func (f *fakeAPI) GetUserList() (*[]api.UserInfo, error)         { return f.users, nil }
func (f *fakeAPI) ReportNodeStatus(*api.NodeStatus) error        { return nil }
func (f *fakeAPI) ReportNodeOnlineUsers(*[]api.OnlineUser) error { return nil }
func (f *fakeAPI) ReportUserTraffic(*[]api.UserTraffic) error    { return nil }
func (f *fakeAPI) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: "fake", NodeID: 1, NodeType: "Vless"}
}
func (f *fakeAPI) GetNodeRule() (*[]api.DetectRule, error) {
	empty := []api.DetectRule{}
	return &empty, nil
}
func (f *fakeAPI) ReportIllegal(*[]api.DetectResult) error { return nil }
func (f *fakeAPI) Debug()                                  {}
