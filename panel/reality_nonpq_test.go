package panel

import (
	"strings"
	"testing"

	"github.com/Vergelab/XrayR/service/controller"
	"github.com/spf13/viper"
	"github.com/xtls/reality"
)

func boolPtr(v bool) *bool { return &v }

func TestAllowsNonPQDefaultAndExplicitFalse(t *testing.T) {
	if !mergeControllerConfig(nil).AllowsNonPQClients() {
		t.Fatal("nil controller config should default to allowing non-PQ clients")
	}
	if !mergeControllerConfig(&controller.Config{}).AllowsNonPQClients() {
		t.Fatal("omitted REALITYAllowNonPQClients should default to true")
	}
	merged := mergeControllerConfig(&controller.Config{REALITYAllowNonPQClients: boolPtr(false)})
	if merged.AllowsNonPQClients() {
		t.Fatal("explicit false was overwritten by the default")
	}
	merged = mergeControllerConfig(&controller.Config{REALITYAllowNonPQClients: boolPtr(true)})
	if !merged.AllowsNonPQClients() {
		t.Fatal("explicit true was lost")
	}
}

func TestViperParsesAllowNonPQFalse(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(`
Nodes:
  - PanelType: NewV2board
    ControllerConfig:
      REALITYAllowNonPQClients: false
`)); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.NodesConfig[0].ControllerConfig.AllowsNonPQClients() {
		t.Fatal("yaml false did not survive unmarshal")
	}

	v = viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(`
Nodes:
  - PanelType: NewV2board
    ControllerConfig:
      ListenIP: 127.0.0.1
`)); err != nil {
		t.Fatal(err)
	}
	cfg = &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.NodesConfig[0].ControllerConfig.AllowsNonPQClients() {
		t.Fatal("omitted yaml key should default to true")
	}
}

func TestResolveAllowNonPQFirstNodeWins(t *testing.T) {
	allow, mixed := resolveREALITYAllowNonPQ([]*NodesConfig{
		{ControllerConfig: &controller.Config{REALITYAllowNonPQClients: boolPtr(true)}},
		{ControllerConfig: &controller.Config{REALITYAllowNonPQClients: boolPtr(false)}},
	})
	if !allow || !mixed {
		t.Fatalf("first true: allow=%v mixed=%v", allow, mixed)
	}
	allow, mixed = resolveREALITYAllowNonPQ([]*NodesConfig{
		{ControllerConfig: &controller.Config{REALITYAllowNonPQClients: boolPtr(false)}},
		nil,
	})
	if allow || !mixed {
		t.Fatalf("first false: allow=%v mixed=%v", allow, mixed)
	}
	allow, mixed = resolveREALITYAllowNonPQ(nil)
	if !allow || mixed {
		t.Fatalf("empty: allow=%v mixed=%v", allow, mixed)
	}
}

func TestApplyAllowNonPQHotReload(t *testing.T) {
	t.Cleanup(func() { reality.SetAllowNonPQClients(true) })

	applyREALITYAllowNonPQ([]*NodesConfig{{
		ControllerConfig: &controller.Config{REALITYAllowNonPQClients: boolPtr(false)},
	}})
	if reality.ProcessAllowsNonPQClients() {
		t.Fatal("apply false did not stick")
	}
	applyREALITYAllowNonPQ([]*NodesConfig{{
		ControllerConfig: &controller.Config{},
	}})
	if !reality.ProcessAllowsNonPQClients() {
		t.Fatal("apply of the default did not turn the process flag back on")
	}
}
