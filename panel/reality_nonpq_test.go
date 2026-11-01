package panel

import (
	"bytes"
	"log"
	"os"
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

func TestResolveAllowNonPQ(t *testing.T) {
	cases := []struct {
		name                 string
		cfg                  *Config
		allow, legacy, mixed bool
		differ               bool
	}{
		{
			name:  "none",
			cfg:   &Config{NodesConfig: []*NodesConfig{{ControllerConfig: &controller.Config{}}}},
			allow: true,
		},
		{
			name:  "nil config",
			cfg:   nil,
			allow: true,
		},
		{
			name:  "top-level only true",
			cfg:   &Config{REALITYAllowNonPQClients: boolPtr(true)},
			allow: true,
		},
		{
			name: "top-level only false",
			cfg: &Config{
				REALITYAllowNonPQClients: boolPtr(false),
				NodesConfig:              []*NodesConfig{{ControllerConfig: &controller.Config{ListenIP: "0.0.0.0"}}},
			},
			allow: false,
		},
		{
			name: "node-only legacy false",
			cfg: &Config{NodesConfig: []*NodesConfig{{
				ControllerConfig: &controller.Config{REALITYAllowNonPQClients: boolPtr(false)},
			}}},
			allow:  false,
			legacy: true,
		},
		{
			name: "node-only first wins when nodes disagree",
			cfg: &Config{NodesConfig: []*NodesConfig{
				{ControllerConfig: &controller.Config{REALITYAllowNonPQClients: boolPtr(true)}},
				{ControllerConfig: &controller.Config{REALITYAllowNonPQClients: boolPtr(false)}},
			}},
			allow:  true,
			legacy: true,
			mixed:  true,
		},
		{
			name: "node-only omitted later node still counts as true",
			cfg: &Config{NodesConfig: []*NodesConfig{
				{ControllerConfig: &controller.Config{REALITYAllowNonPQClients: boolPtr(false)}},
				nil,
			}},
			allow:  false,
			legacy: true,
			mixed:  true,
		},
		{
			name: "node-only omitted first node still wins as true",
			cfg: &Config{NodesConfig: []*NodesConfig{
				{ControllerConfig: &controller.Config{}},
				{ControllerConfig: &controller.Config{REALITYAllowNonPQClients: boolPtr(false)}},
			}},
			allow:  true,
			legacy: true,
			mixed:  true,
		},
		{
			name: "both top-level wins when they differ",
			cfg: &Config{
				REALITYAllowNonPQClients: boolPtr(true),
				NodesConfig: []*NodesConfig{{
					ControllerConfig: &controller.Config{REALITYAllowNonPQClients: boolPtr(false)},
				}},
			},
			allow:  true,
			differ: true,
		},
		{
			name: "both agree so top-level wins quietly",
			cfg: &Config{
				REALITYAllowNonPQClients: boolPtr(false),
				NodesConfig: []*NodesConfig{
					{ControllerConfig: &controller.Config{REALITYAllowNonPQClients: boolPtr(false)}},
					{ControllerConfig: &controller.Config{REALITYAllowNonPQClients: boolPtr(false)}},
				},
			},
			allow: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allow, legacy, mixed, differ := resolveREALITYAllowNonPQ(tc.cfg)
			if allow != tc.allow || legacy != tc.legacy || mixed != tc.mixed || differ != tc.differ {
				t.Fatalf("allow=%v legacy=%v mixed=%v differ=%v, want allow=%v legacy=%v mixed=%v differ=%v",
					allow, legacy, mixed, differ, tc.allow, tc.legacy, tc.mixed, tc.differ)
			}
		})
	}
}

func TestApplyAllowNonPQHotReload(t *testing.T) {
	t.Cleanup(func() { reality.SetAllowNonPQClients(true) })

	applyREALITYAllowNonPQ(&Config{REALITYAllowNonPQClients: boolPtr(false)})
	if reality.ProcessAllowsNonPQClients() {
		t.Fatal("top-level false did not stick")
	}
	applyREALITYAllowNonPQ(&Config{NodesConfig: []*NodesConfig{{
		ControllerConfig: &controller.Config{},
	}}})
	if !reality.ProcessAllowsNonPQClients() {
		t.Fatal("omitted key did not turn the process flag back on")
	}
	applyREALITYAllowNonPQ(&Config{NodesConfig: []*NodesConfig{{
		ControllerConfig: &controller.Config{REALITYAllowNonPQClients: boolPtr(false)},
	}}})
	if reality.ProcessAllowsNonPQClients() {
		t.Fatal("legacy per-node false did not stick")
	}
}

func TestApplyAllowNonPQLogs(t *testing.T) {
	t.Cleanup(func() { reality.SetAllowNonPQClients(true) })
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	applyREALITYAllowNonPQ(&Config{NodesConfig: []*NodesConfig{{
		ControllerConfig: &controller.Config{REALITYAllowNonPQClients: boolPtr(false)},
	}}})
	if !strings.Contains(buf.String(), "deprecated") || !strings.Contains(buf.String(), "top-level REALITYAllowNonPQClients") {
		t.Fatalf("legacy apply log = %q", buf.String())
	}

	buf.Reset()
	applyREALITYAllowNonPQ(&Config{
		REALITYAllowNonPQClients: boolPtr(true),
		NodesConfig: []*NodesConfig{{
			ControllerConfig: &controller.Config{REALITYAllowNonPQClients: boolPtr(false)},
		}},
	})
	if !strings.Contains(buf.String(), "overrides") {
		t.Fatalf("differing apply log = %q", buf.String())
	}

	buf.Reset()
	applyREALITYAllowNonPQ(&Config{REALITYAllowNonPQClients: boolPtr(true)})
	if buf.Len() != 0 {
		t.Fatalf("top-level only should be quiet, log = %q", buf.String())
	}
}

func TestExampleConfigTopLevelAllowNonPQ(t *testing.T) {
	raw, err := os.ReadFile("../release/config/config.yml.example")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "接受只有") || strings.Contains(text, "Trade-off:") {
		t.Fatal("example still has the long REALITY comment block")
	}
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.REALITYAllowNonPQClients == nil || !*cfg.REALITYAllowNonPQClients {
		t.Fatal("example top-level REALITYAllowNonPQClients should be true")
	}
	for i, node := range cfg.NodesConfig {
		if node != nil && node.ControllerConfig != nil && node.ControllerConfig.REALITYAllowNonPQClients != nil {
			t.Fatalf("node %d still sets REALITYAllowNonPQClients", i)
		}
	}
	allow, legacy, mixed, differ := resolveREALITYAllowNonPQ(cfg)
	if !allow || legacy || mixed || differ {
		t.Fatalf("example resolve allow=%v legacy=%v mixed=%v differ=%v", allow, legacy, mixed, differ)
	}
}

func TestViperResolvesTopLevelAndLegacy(t *testing.T) {
	parse := func(t *testing.T, yaml string) *Config {
		t.Helper()
		v := viper.New()
		v.SetConfigType("yaml")
		if err := v.ReadConfig(strings.NewReader(yaml)); err != nil {
			t.Fatal(err)
		}
		cfg := &Config{}
		if err := v.Unmarshal(cfg); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	cases := []struct {
		name   string
		yaml   string
		allow  bool
		legacy bool
		differ bool
	}{
		{
			name: "top-level only",
			yaml: `
REALITYAllowNonPQClients: false
Nodes:
  - PanelType: NewV2board
    ControllerConfig:
      ListenIP: 127.0.0.1
`,
			allow: false,
		},
		{
			name: "node-only legacy",
			yaml: `
Nodes:
  - PanelType: NewV2board
    ControllerConfig:
      REALITYAllowNonPQClients: false
`,
			allow:  false,
			legacy: true,
		},
		{
			name: "both top-level wins",
			yaml: `
REALITYAllowNonPQClients: true
Nodes:
  - PanelType: NewV2board
    ControllerConfig:
      REALITYAllowNonPQClients: false
`,
			allow:  true,
			differ: true,
		},
		{
			name: "none",
			yaml: `
Nodes:
  - PanelType: NewV2board
    ControllerConfig:
      ListenIP: 127.0.0.1
`,
			allow: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allow, legacy, _, differ := resolveREALITYAllowNonPQ(parse(t, tc.yaml))
			if allow != tc.allow || legacy != tc.legacy || differ != tc.differ {
				t.Fatalf("allow=%v legacy=%v differ=%v, want allow=%v legacy=%v differ=%v",
					allow, legacy, differ, tc.allow, tc.legacy, tc.differ)
			}
		})
	}
}
