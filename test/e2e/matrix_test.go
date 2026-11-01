//go:build e2e

package e2e

import (
	"bytes"
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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Vergelab/XrayR/api"
	_ "github.com/Vergelab/XrayR/cmd/distro/all"
	"github.com/Vergelab/XrayR/common/mylego"
	"github.com/Vergelab/XrayR/panel"
	"github.com/Vergelab/XrayR/service/controller"
)

const (
	userUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
	shortID  = "0123456789abcdef"
	sni      = "www.microsoft.com"
)

func TestREALITYFingerprintMatrix(t *testing.T) {
	bins := clientBins(t)
	fps := []string{"chrome", "firefox", "safari", "edge", "ios", "qq", "random", "randomized"}

	var report strings.Builder
	report.WriteString("mode\tclient\tfingerprint\tresult\n")

	for _, allow := range []bool{true, false} {
		mode := "on"
		if !allow {
			mode = "off"
		}
		t.Run(mode, func(t *testing.T) {
			env := startREALITY(t, allow)
			for _, client := range []string{"xray", "mihomo", "mihomo-pq", "sing-box"} {
				for _, fp := range fps {
					runs := 1
					if fp == "random" || fp == "randomized" {
						runs = 10
					}
					pass, rejected, last := 0, 0, ""
					for i := 0; i < runs; i++ {
						kind, detail := connectOnce(t, env, bins, client, fp)
						switch kind {
						case "pass":
							pass++
						case "rejected":
							rejected++
							last = detail
						default:
							last = detail
						}
					}
					result := fmt.Sprintf("%d/%d", pass, runs)
					if rejected == runs {
						result = "client-rejected"
					} else if rejected > 0 {
						result = fmt.Sprintf("%d/%d pass, %d client-rejected", pass, runs, rejected)
					}
					line := fmt.Sprintf("%s\t%s\t%s\t%s", mode, client, fp, result)
					if last != "" && pass != runs {
						line += "\t" + oneLine(last)
					}
					t.Log(line)
					report.WriteString(line + "\n")
					checkExpect(t, allow, client, fp, pass, rejected, runs, last)
				}
			}
			if allow {
				assertNegotiatedGroup(t, env, bins.xray, "chrome", true)
				assertNegotiatedGroup(t, env, bins.mihomo, "chrome", true, mihomoPQ(true))
				logNegotiatedGroup(t, env, bins.xray, "edge")
			} else {
				assertNegotiatedGroup(t, env, bins.xray, "chrome", true)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "matrix.txt")
	if err := os.WriteFile(path, []byte(report.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	// Keep a copy outside the temp dir so the run log is easy to read back.
	if err := os.WriteFile("/tmp/reality-matrix.txt", []byte(report.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("matrix written to /tmp/reality-matrix.txt and %s", path)
}

type bins struct {
	xray, mihomo, singbox, asset string
}

func clientBins(t *testing.T) bins {
	t.Helper()
	root := os.Getenv("XRAYR_E2E_CLIENTS")
	if root == "" {
		root = "/tmp/xrayr-e2e-clients"
	}
	b := bins{
		xray:    filepath.Join(root, "xray", "xray"),
		mihomo:  filepath.Join(root, "mihomo"),
		singbox: filepath.Join(root, "sing-box"),
		asset:   filepath.Join(root, "xray"),
	}
	for _, p := range []string{b.xray, b.mihomo, b.singbox} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("missing client %s: %v", p, err)
		}
	}
	return b
}

type realityEnv struct {
	nodePort int
	httpAddr string
	pub      string
}

func startREALITY(t *testing.T, allow bool) realityEnv {
	t.Helper()
	httpLn := mustListen(t)
	t.Cleanup(func() { httpLn.Close() })
	go http.Serve(httpLn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "e2e-ok")
	}))

	tlsRaw := mustListen(t)
	t.Cleanup(func() { tlsRaw.Close() })
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
	nodeLn := mustListen(t)
	nodePort := nodeLn.Addr().(*net.TCPAddr).Port
	nodeLn.Close()
	_, tlsPort, err := net.SplitHostPort(tlsRaw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	mock := &mockPanel{privateKey: privateKey, shortID: shortID, nodePort: nodePort, tlsPort: tlsPort}
	mockLn := mustListen(t)
	t.Cleanup(func() { mockLn.Close() })
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
				UpdatePeriodic:            3600,
				DisableLocalREALITYConfig: true,
				REALITYAllowNonPQClients:  boolPtr(allow),
				REALITYConfigs: &controller.REALITYConfig{
					Show:        true,
					Dest:        sni + ":443",
					ServerNames: []string{sni},
					ShortIds:    []string{""},
				},
				CertConfig: &mylego.CertConfig{CertMode: "none"},
			},
		}},
	}
	p := panel.New(cfg)
	startPanel(t, p)
	t.Cleanup(func() { p.Close() })
	waitListen(t, fmt.Sprintf("127.0.0.1:%d", nodePort))
	return realityEnv{nodePort: nodePort, httpAddr: httpLn.Addr().String(), pub: publicKey}
}

func boolPtr(v bool) *bool { return &v }

func assertNegotiatedGroup(t *testing.T, env realityEnv, bin, fp string, wantPQ bool, extra ...func(*clientSpec)) {
	t.Helper()
	spec := clientSpec{bin: bin, kind: "xray", fp: fp}
	if strings.Contains(bin, "mihomo") {
		spec.kind = "mihomo"
	}
	for _, fn := range extra {
		fn(&spec)
	}
	out := captureStdout(t, func() {
		kind, detail := connectSpec(t, env, spec)
		if kind != "pass" {
			t.Fatalf("group check %s %s: %s (%s)", spec.kind, fp, kind, detail)
		}
	})
	needle := "is using X25519MLKEM768 for TLS' communication: true"
	if !wantPQ {
		needle = "is using X25519MLKEM768 for TLS' communication: false"
	}
	if !strings.Contains(out, needle) {
		t.Fatalf("negotiated group for %s %s, want %q, log:\n%s", spec.kind, fp, needle, out)
	}
	t.Logf("negotiated group %s %s pq=%v", spec.kind, fp, wantPQ)
}

func logNegotiatedGroup(t *testing.T, env realityEnv, bin, fp string) {
	t.Helper()
	spec := clientSpec{bin: bin, kind: "xray", fp: fp}
	out := captureStdout(t, func() {
		kind, detail := connectSpec(t, env, spec)
		if kind != "pass" {
			t.Fatalf("group log %s %s: %s (%s)", spec.kind, fp, kind, detail)
		}
	})
	pq := strings.Contains(out, "is using X25519MLKEM768 for TLS' communication: true")
	classic := strings.Contains(out, "is using X25519MLKEM768 for TLS' communication: false")
	t.Logf("negotiated group %s %s pq=%v x25519=%v", fp, spec.kind, pq, classic)
}

func mihomoPQ(on bool) func(*clientSpec) {
	return func(s *clientSpec) { s.pq = on }
}

type clientSpec struct {
	bin, kind, fp string
	pq            bool
}

func connectOnce(t *testing.T, env realityEnv, b bins, client, fp string) (string, string) {
	t.Helper()
	spec := clientSpec{fp: fp}
	switch client {
	case "xray":
		spec.bin, spec.kind = b.xray, "xray"
	case "mihomo":
		spec.bin, spec.kind = b.mihomo, "mihomo"
	case "mihomo-pq":
		spec.bin, spec.kind, spec.pq = b.mihomo, "mihomo", true
	case "sing-box":
		spec.bin, spec.kind = b.singbox, "sing-box"
	default:
		t.Fatalf("unknown client %s", client)
	}
	return connectSpec(t, env, spec)
}

func connectSpec(t *testing.T, env realityEnv, spec clientSpec) (string, string) {
	t.Helper()
	dir := t.TempDir()
	socks := freePort(t)
	cfgPath, err := writeClientConfig(dir, spec, env, socks)
	if err != nil {
		return "error", err.Error()
	}
	cmd, err := clientCommand(spec, cfgPath, dir)
	if err != nil {
		return "error", err.Error()
	}
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(clientBinsPath()))
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		return "error", err.Error()
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socks)
	if err := waitListenQuiet(socksAddr, 8*time.Second); err != nil {
		text := output.String()
		if clientRejected(text, spec.fp) {
			return "rejected", text
		}
		return "fail", "socks not up: " + oneLine(text)
	}
	if err := httpGet(socksAddr, env.httpAddr); err != nil {
		return "fail", err.Error() + " " + oneLine(output.String())
	}
	return "pass", ""
}

func clientBinsPath() string {
	root := os.Getenv("XRAYR_E2E_CLIENTS")
	if root == "" {
		root = "/tmp/xrayr-e2e-clients"
	}
	return filepath.Join(root, "xray", "xray")
}

func clientRejected(text, fp string) bool {
	low := strings.ToLower(text)
	if !strings.Contains(low, strings.ToLower(fp)) && !strings.Contains(low, "fingerprint") {
		return false
	}
	for _, hint := range []string{"unknown", "invalid", "unsupported", "not found", "no such"} {
		if strings.Contains(low, hint) {
			return true
		}
	}
	return false
}

func writeClientConfig(dir string, spec clientSpec, env realityEnv, socks int) (string, error) {
	switch spec.kind {
	case "xray":
		raw := fmt.Sprintf(`{
			"log": {"loglevel": "warning"},
			"inbounds": [{
				"listen": "127.0.0.1", "port": %d, "protocol": "socks",
				"settings": {"udp": false}
			}],
			"outbounds": [{
				"protocol": "vless",
				"settings": {"vnext": [{
					"address": "127.0.0.1", "port": %d,
					"users": [{"id": %q, "encryption": "none", "flow": "xtls-rprx-vision"}]
				}]},
				"streamSettings": {
					"network": "tcp", "security": "reality",
					"realitySettings": {
						"serverName": %q, "fingerprint": %q,
						"publicKey": %q, "shortId": %q
					}
				}
			}]
		}`, socks, env.nodePort, userUUID, sni, spec.fp, env.pub, shortID)
		path := filepath.Join(dir, "config.json")
		return path, os.WriteFile(path, []byte(raw), 0o644)
	case "mihomo":
		pq := "false"
		if spec.pq {
			pq = "true"
		}
		raw := fmt.Sprintf(`mixed-port: %d
allow-lan: false
bind-address: 127.0.0.1
ipv6: false
find-process-mode: off
geo-auto-update: false
log-level: warning
mode: rule
proxies:
  - name: reality
    type: vless
    server: 127.0.0.1
    port: %d
    uuid: %s
    network: tcp
    udp: false
    tls: true
    flow: xtls-rprx-vision
    servername: %s
    client-fingerprint: %s
    reality-opts:
      public-key: %s
      short-id: %s
      support-x25519mlkem768: %s
rules:
  - MATCH,reality
`, socks, env.nodePort, userUUID, sni, spec.fp, env.pub, shortID, pq)
		path := filepath.Join(dir, "config.yaml")
		return path, os.WriteFile(path, []byte(raw), 0o644)
	case "sing-box":
		raw := fmt.Sprintf(`{
			"log": {"level": "warn"},
			"inbounds": [{
				"type": "socks", "tag": "socks-in",
				"listen": "127.0.0.1", "listen_port": %d
			}],
			"outbounds": [{
				"type": "vless", "tag": "proxy",
				"server": "127.0.0.1", "server_port": %d,
				"uuid": %q, "flow": "xtls-rprx-vision",
				"tls": {
					"enabled": true, "server_name": %q,
					"utls": {"enabled": true, "fingerprint": %q},
					"reality": {"enabled": true, "public_key": %q, "short_id": %q}
				}
			}],
			"route": {"final": "proxy"}
		}`, socks, env.nodePort, userUUID, sni, spec.fp, env.pub, shortID)
		path := filepath.Join(dir, "config.json")
		return path, os.WriteFile(path, []byte(raw), 0o644)
	default:
		return "", fmt.Errorf("unknown kind %s", spec.kind)
	}
}

func clientCommand(spec clientSpec, cfg, dir string) (*exec.Cmd, error) {
	var cmd *exec.Cmd
	switch spec.kind {
	case "xray":
		cmd = exec.Command(spec.bin, "run", "-c", cfg)
	case "mihomo":
		cmd = exec.Command(spec.bin, "-d", dir, "-f", cfg)
	case "sing-box":
		cmd = exec.Command(spec.bin, "run", "-c", cfg, "-D", dir)
	default:
		return nil, fmt.Errorf("unknown kind %s", spec.kind)
	}
	cmd.Dir = dir
	return cmd, nil
}

func checkExpect(t *testing.T, allow bool, client, fp string, pass, rejected, runs int, last string) {
	t.Helper()
	want := expect(allow, client, fp)
	switch want {
	case "pass":
		if pass != runs || rejected != 0 {
			t.Errorf("%s %s allow=%v: got %d/%d rejected=%d (%s)", client, fp, allow, pass, runs, rejected, oneLine(last))
		}
	case "fail":
		if pass != 0 || rejected != 0 {
			t.Errorf("%s %s allow=%v: want upstream fail, got %d/%d rejected=%d (%s)", client, fp, allow, pass, runs, rejected, oneLine(last))
		}
	case "record":
		if rejected == runs {
			t.Logf("recorded client rejection: %s %s (%s)", client, fp, oneLine(last))
		}
	}
}

func expect(allow bool, client, fp string) string {
	switch fp {
	case "random", "randomized":
		// randomized is not required to be 10/10. Xray's uTLS
		// HelloRandomizedALPN always sends an X25519 share and, about a
		// third of the time, also lists X25519MLKEM768 with no key share.
		// mihomo with support-x25519mlkem768 does the same kind of mix.
		// The decoy answers with a 93-byte HelloRetryRequest. Upstream
		// REALITY drops that (the share is not 32 bytes or ML-KEM sized)
		// after REALITY auth has already succeeded. mihomo's default
		// randomized and sing-box's randomized pick a complete fingerprint
		// and stay at 10/10.
		return "record"
	}
	if allow {
		return "pass"
	}
	switch client {
	case "xray":
		switch fp {
		case "chrome", "firefox", "safari":
			return "pass"
		default:
			return "fail"
		}
	case "mihomo":
		return "fail"
	case "mihomo-pq":
		if fp == "chrome" {
			return "pass"
		}
		return "fail"
	case "sing-box":
		return "fail"
	default:
		return "record"
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		os.Stdout = old
		_ = w.Close()
		<-done
		_ = r.Close()
	}
	defer restore()
	fn()
	restore()
	return buf.String()
}

func httpGet(socksAddr, dest string) error {
	conn, err := socksDial(socksAddr, dest)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+dest+"\r\nConnection: close\r\n\r\n"); err != nil {
		return err
	}
	body, err := io.ReadAll(conn)
	if len(body) == 0 && err != nil {
		return err
	}
	if !strings.Contains(string(body), "e2e-ok") {
		return fmt.Errorf("response %q", body)
	}
	return nil
}

func socksDial(socksAddr, dest string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", socksAddr, 3*time.Second)
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

func waitListen(t *testing.T, addr string) {
	t.Helper()
	if err := waitListenQuiet(addr, 8*time.Second); err != nil {
		t.Fatal(err)
	}
}

func waitListenQuiet(addr string, d time.Duration) error {
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		last = err
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("not listening on %s: %v", addr, last)
}

func freePort(t *testing.T) int {
	t.Helper()
	ln := mustListen(t)
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
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
		DNSNames:     []string{sni},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
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

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " | ")
	if len(s) > 400 {
		return s[:400]
	}
	return s
}

type mockPanel struct {
	privateKey string
	shortID    string
	nodePort   int
	tlsPort    string
}

func (m *mockPanel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("token") != "test-token" {
		http.Error(w, "token", http.StatusForbidden)
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/config"):
		port, _ := strconv.Atoi(m.tlsPort)
		writeJSON(w, map[string]any{
			"server_port": m.nodePort,
			"network":     "tcp",
			"flow":        "xtls-rprx-vision",
			"tls":         2,
			"tls_settings": map[string]any{
				"dest":        "127.0.0.1",
				"server_port": port,
				"server_name": sni,
				"public_key":  "ignored",
				"private_key": m.privateKey,
				"short_id":    m.shortID,
			},
			"base_config": map[string]any{"push_interval": 60, "pull_interval": 60},
		})
	case strings.HasSuffix(r.URL.Path, "/user"):
		writeJSON(w, map[string]any{"users": []any{map[string]any{
			"id": 1, "uuid": userUUID, "speed_limit": 0,
		}}})
	case strings.HasSuffix(r.URL.Path, "/alivelist"):
		http.NotFound(w, r)
	case strings.HasSuffix(r.URL.Path, "/push"), strings.HasSuffix(r.URL.Path, "/alive"):
		writeJSON(w, map[string]any{"status": "success", "data": true})
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
