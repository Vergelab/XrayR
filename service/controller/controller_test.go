package controller_test

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"testing"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/Vergelab/XrayR/api"
	"github.com/Vergelab/XrayR/api/sspanel"
	_ "github.com/Vergelab/XrayR/cmd/distro/all"
	"github.com/Vergelab/XrayR/common/mylego"
	. "github.com/Vergelab/XrayR/service/controller"
)

func TestController(t *testing.T) {
	if os.Getenv("XRAYR_LIVE_PANEL") == "" {
		t.Skip("skipping: set XRAYR_LIVE_PANEL=1 to run against a live panel")
	}
	serverConfig := &conf.Config{
		Stats:     &conf.StatsConfig{},
		LogConfig: &conf.LogConfig{LogLevel: "debug"},
	}
	policyConfig := &conf.PolicyConfig{}
	policyConfig.Levels = map[uint32]*conf.Policy{0: {
		StatsUserUplink:   true,
		StatsUserDownlink: true,
	}}
	serverConfig.Policy = policyConfig
	config, _ := serverConfig.Build()

	// config := &core.Config{
	// 	App: []*serial.TypedMessage{
	// 		serial.ToTypedMessage(&dispatcher.Config{}),
	// 		serial.ToTypedMessage(&proxyman.InboundConfig{}),
	// 		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
	// 		serial.ToTypedMessage(&stats.Config{}),
	// 	}}

	server, err := core.New(config)
	if err != nil {
		t.Fatalf("failed to create instance: %s", err)
	}
	defer server.Close()
	if err = server.Start(); err != nil {
		t.Errorf("Failed to start instance: %s", err)
	}
	certConfig := &mylego.CertConfig{
		CertMode:   "http",
		CertDomain: "test.ss.tk",
		Provider:   "alidns",
		Email:      "ss@ss.com",
	}
	controlerConfig := &Config{
		UpdatePeriodic: 5,
		CertConfig:     certConfig,
	}
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:667",
		Key:      "123",
		NodeID:   41,
		NodeType: "V2ray",
	}
	apiClient := sspanel.New(apiConfig)
	c := New(server, apiClient, controlerConfig, "SSpanel")
	fmt.Println("Sleep 1s")
	err = c.Start()
	if err != nil {
		t.Error(err)
	}
	// Explicitly triggering GC to remove garbage from config loading.
	runtime.GC()

	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
		<-osSignals
	}
}
