package mylego

import (
	"os"
	"strings"
	"testing"
)

func TestRecoverAssignsNamedErr(t *testing.T) {
	l := &LegoCMD{}
	_, _, err := l.DNSCert()
	if err == nil {
		t.Fatal("panic was recovered as a nil error")
	}
	_, _, err = l.HTTPCert()
	if err == nil {
		t.Fatal("http panic was recovered as a nil error")
	}
	_, _, _, err = l.RenewCert()
	if err == nil {
		t.Fatal("renew panic was recovered as a nil error")
	}
}

func TestDNSEnvIsUnsetAfterUse(t *testing.T) {
	const key = "XRAYR_TEST_DNS_SECRET"
	_ = os.Unsetenv(key)
	l := &LegoCMD{C: &CertConfig{DNSEnv: map[string]string{key: "secret"}}}
	cleanup := l.setDNSEnv()
	if os.Getenv(key) != "secret" {
		t.Fatalf("env = %q", os.Getenv(key))
	}
	cleanup()
	if v, ok := os.LookupEnv(key); ok {
		t.Fatalf("env still set: %s", v)
	}
	t.Setenv(key, "kept")
	l = &LegoCMD{C: &CertConfig{DNSEnv: map[string]string{strings.ToLower(key): "secret"}}}
	cleanup = l.setDNSEnv()
	cleanup()
	if os.Getenv(key) != "kept" {
		t.Fatalf("previous env = %q", os.Getenv(key))
	}
}
