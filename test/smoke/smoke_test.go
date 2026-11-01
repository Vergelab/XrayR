//go:build smoke

package smoke

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Vergelab/XrayR/api"
	_ "github.com/Vergelab/XrayR/cmd/distro/all"
	"github.com/Vergelab/XrayR/common/limiter"
	"github.com/Vergelab/XrayR/common/mylego"
	"github.com/Vergelab/XrayR/panel"
	"github.com/Vergelab/XrayR/service/controller"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

func TestMockXboardREALITYVision(t *testing.T) {
	httpLn := mustListen(t)
	defer httpLn.Close()
	go http.Serve(httpLn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "smoke-ok")
	}))

	tlsRaw := mustListen(t)
	defer tlsRaw.Close()
	tlsLn := tls.NewListener(tlsRaw, &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 2048)
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := base64.RawURLEncoding.EncodeToString(priv.Bytes())
	publicKey := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	const (
		userUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
		shortID  = "0123456789abcdef"
	)
	nodeLn := mustListen(t)
	nodePort := nodeLn.Addr().(*net.TCPAddr).Port
	nodeLn.Close()
	_, tlsPort, err := net.SplitHostPort(tlsRaw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	mock := newMock(privateKey, shortID, nodePort, tlsPort)
	mockLn := mustListen(t)
	defer mockLn.Close()
	go http.Serve(mockLn, mock)

	cfg := &panel.Config{
		LogConfig: &panel.LogConfig{Level: "warning"},
		NodesConfig: []*panel.NodesConfig{{
			PanelType: "NewV2board",
			ApiConfig: &api.Config{
				APIHost:     "http://" + mockLn.Addr().String(),
				Key:         "test-token",
				NodeID:      1,
				NodeType:    "Vless",
				EnableVless: true,
				VlessFlow:   "xtls-rprx-vision",
				Timeout:     5,
			},
			ControllerConfig: &controller.Config{
				ListenIP:                  "127.0.0.1",
				SendIP:                    "0.0.0.0",
				UpdatePeriodic:            1,
				DeviceOnlineMinTraffic:    0,
				DisableLocalREALITYConfig: true,
				REALITYConfigs: &controller.REALITYConfig{
					Dest:        "www.microsoft.com:443",
					ServerNames: []string{"www.microsoft.com"},
					ShortIds:    []string{""},
				},
				CertConfig: &mylego.CertConfig{CertMode: "none"},
			},
		}},
	}
	p := panel.New(cfg)
	startPanel(t, p)
	defer p.Close()

	socksAddr, client, err := startClient(t, nodePort, userUUID, publicKey, shortID)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if err := fetch(socksAddr, httpLn.Addr().String()); err != nil {
		t.Fatalf("initial REALITY+Vision fetch: %v", err)
	}
	t.Log("smoke-ok through SOCKS, fingerprint chrome, numeric tls server_port")

	// (b) failed push puts the bytes back; the next push includes them.
	mark := mock.pushLen()
	mock.failPush.Store(true)
	if err := fetch(socksAddr, httpLn.Addr().String()); err != nil {
		t.Fatal(err)
	}
	failedPush := mock.waitPush(t, true, mark)
	mock.failPush.Store(false)
	okPush := mock.waitPush(t, false, mark)
	if okPush.up+okPush.down < failedPush.up+failedPush.down {
		t.Fatalf("push bytes failed=%+v next=%+v", failedPush, okPush)
	}
	t.Logf("push re-added bytes: failed=%+v next=%+v", failedPush, okPush)

	// (d) a bad REALITY payload keeps the old inbound serving.
	mock.breakReality.Store(true)
	time.Sleep(1500 * time.Millisecond)
	if err := fetch(socksAddr, httpLn.Addr().String()); err != nil {
		t.Fatalf("old inbound stopped after a bad REALITY payload: %v", err)
	}
	t.Log("bad REALITY payload kept the old inbound")

	// (a) an empty user list removes the user.
	mock.emptyUsers.Store(true)
	time.Sleep(1500 * time.Millisecond)
	if err := fetch(socksAddr, httpLn.Addr().String()); err == nil {
		t.Fatal("empty user list left the user connected")
	}
	t.Log("empty user list removed the user")

	// (c) device_limit 1 rejects a second local IP.
	lim := limiter.New()
	users := []api.UserInfo{{UID: 1, Email: "u@x", DeviceLimit: 1}}
	if err := lim.AddInboundLimiter("tag", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, reject := lim.GetUserBucket("tag", "tag|u@x|1", "10.0.0.1", true); reject {
		t.Fatal("first ip rejected")
	}
	if _, _, reject := lim.GetUserBucket("tag", "tag|u@x|1", "10.0.0.2", true); !reject {
		t.Fatal("second ip was not rejected")
	}
	t.Log("device_limit 1 rejected the second local IP")
}

type mockPanel struct {
	mu           sync.Mutex
	privateKey   string
	shortID      string
	nodePort     int
	tlsPort      string
	pushes       []pushRecord
	failPush     atomic.Bool
	breakReality atomic.Bool
	emptyUsers   atomic.Bool
}

func newMock(privateKey, shortID string, nodePort int, tlsPort string) *mockPanel {
	return &mockPanel{privateKey: privateKey, shortID: shortID, nodePort: nodePort, tlsPort: tlsPort}
}

func (m *mockPanel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("token") != "test-token" {
		http.Error(w, "token", http.StatusForbidden)
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/config"):
		key := m.privateKey
		if m.breakReality.Load() {
			key = ""
		}
		port, _ := strconv.Atoi(m.tlsPort)
		writeJSON(w, map[string]any{
			"server_port": m.nodePort,
			"network":     "tcp",
			"flow":        "xtls-rprx-vision",
			"tls":         2,
			"tls_settings": map[string]any{
				"dest":        "127.0.0.1",
				"server_port": port, // number, not a string
				"server_name": "www.microsoft.com",
				"public_key":  "ignored",
				"private_key": key,
				"short_id":    m.shortID,
			},
			"base_config": map[string]any{"push_interval": 1, "pull_interval": 1},
		})
	case strings.HasSuffix(r.URL.Path, "/user"):
		if m.emptyUsers.Load() {
			writeJSON(w, map[string]any{"users": []any{}})
			return
		}
		writeJSON(w, map[string]any{"users": []any{map[string]any{
			"id": 1, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "speed_limit": 0,
		}}})
	case strings.HasSuffix(r.URL.Path, "/alivelist"):
		http.NotFound(w, r)
	case strings.HasSuffix(r.URL.Path, "/push"):
		var payload map[string][]int64
		_ = json.NewDecoder(r.Body).Decode(&payload)
		var up, down int64
		for _, pair := range payload {
			if len(pair) == 2 {
				up += pair[0]
				down += pair[1]
			}
		}
		failed := m.failPush.Load()
		m.mu.Lock()
		m.pushes = append(m.pushes, pushRecord{up: up, down: down, failed: failed})
		m.mu.Unlock()
		if failed {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"status":"fail"}`))
			return
		}
		writeJSON(w, map[string]any{"status": "success", "data": true})
	case strings.HasSuffix(r.URL.Path, "/alive"):
		writeJSON(w, map[string]any{"status": "success", "data": true})
	default:
		http.NotFound(w, r)
	}
}

type pushRecord struct {
	up, down int64
	failed   bool
}

func (m *mockPanel) waitPush(t *testing.T, wantFail bool, after int) pushRecord {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		for i := after; i < len(m.pushes); i++ {
			if m.pushes[i].failed == wantFail && m.pushes[i].up+m.pushes[i].down > 0 {
				got := m.pushes[i]
				m.mu.Unlock()
				return got
			}
		}
		n := len(m.pushes)
		m.mu.Unlock()
		_ = n
		time.Sleep(200 * time.Millisecond)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t.Fatalf("timed out waiting for push failed=%v after %d, have %#v", wantFail, after, m.pushes)
	return pushRecord{}
}

func (m *mockPanel) pushLen() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pushes)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func startPanel(t *testing.T, p *panel.Panel) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("panel start: %v", recovered)
		}
	}()
	p.Start()
}

func startClient(t *testing.T, nodePort int, uuid, publicKey, shortID string) (string, *core.Instance, error) {
	t.Helper()
	socksLn := mustListen(t)
	socksPort := socksLn.Addr().(*net.TCPAddr).Port
	socksLn.Close()
	raw := fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": %d,
			"protocol": "socks",
			"settings": {"udp": false}
		}],
		"outbounds": [{
			"protocol": "vless",
			"settings": {"vnext": [{
				"address": "127.0.0.1",
				"port": %d,
				"users": [{"id": %q, "encryption": "none", "flow": "xtls-rprx-vision"}]
			}]},
			"streamSettings": {
				"network": "tcp",
				"security": "reality",
				"realitySettings": {
					"serverName": "www.microsoft.com",
					"fingerprint": "chrome",
					"publicKey": %q,
					"shortId": %q
				}
			}
		}]
	}`, socksPort, nodePort, uuid, publicKey, shortID)
	var clientConf conf.Config
	if err := json.Unmarshal([]byte(raw), &clientConf); err != nil {
		return "", nil, err
	}
	pb, err := clientConf.Build()
	if err != nil {
		return "", nil, err
	}
	instance, err := core.New(pb)
	if err != nil {
		return "", nil, err
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		return "", nil, err
	}
	return fmt.Sprintf("127.0.0.1:%d", socksPort), instance, nil
}

func fetch(socksAddr, dest string) error {
	var last error
	for i := 0; i < 20; i++ {
		last = httpGet(socksAddr, dest)
		if last == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return last
}

func httpGet(socksAddr, dest string) error {
	conn, err := socksDial(socksAddr, dest)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+dest+"\r\nConnection: close\r\n\r\n"); err != nil {
		return err
	}
	body, err := io.ReadAll(conn)
	if len(body) == 0 && err != nil {
		return err
	}
	if !strings.Contains(string(body), "smoke-ok") {
		return fmt.Errorf("response %q", body)
	}
	return nil
}

func socksDial(socksAddr, dest string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return nil, err
	}
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	ip := net.ParseIP(host).To4()
	if ip == nil {
		conn.Close()
		return nil, fmt.Errorf("dest %s is not ipv4", dest)
	}
	req := append([]byte{0x05, 0x01, 0x00, 0x01}, ip...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("socks status %d", resp[1])
	}
	return conn, nil
}

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"www.microsoft.com"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
