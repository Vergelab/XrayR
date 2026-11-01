package panel

import (
	"fmt"

	"github.com/Vergelab/XrayR/api"
	"github.com/Vergelab/XrayR/service/controller"
)

// Validate checks a freshly parsed config before it replaces a running panel.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}
	if len(c.NodesConfig) == 0 {
		return fmt.Errorf("no nodes configured")
	}
	for i, node := range c.NodesConfig {
		if node == nil {
			return fmt.Errorf("node %d is nil", i)
		}
		if node.PanelType == "" {
			return fmt.Errorf("node %d is missing PanelType", i)
		}
		if node.ApiConfig == nil {
			return fmt.Errorf("node %d is missing ApiConfig", i)
		}
	}
	return nil
}

type Config struct {
	LogConfig          *LogConfig        `mapstructure:"Log"`
	DnsConfigPath      string            `mapstructure:"DnsConfigPath"`
	InboundConfigPath  string            `mapstructure:"InboundConfigPath"`
	OutboundConfigPath string            `mapstructure:"OutboundConfigPath"`
	RouteConfigPath    string            `mapstructure:"RouteConfigPath"`
	ConnectionConfig   *ConnectionConfig `mapstructure:"ConnectionConfig"`
	// REALITYAllowNonPQClients accepts REALITY ClientHellos that offer only
	// X25519. Nil means true, including when the key is omitted. Applied once,
	// process-wide, at startup and on hot reload. A per-node
	// ControllerConfig.REALITYAllowNonPQClients is still parsed for old
	// configs; this key wins when both are set.
	REALITYAllowNonPQClients *bool          `mapstructure:"REALITYAllowNonPQClients"`
	NodesConfig              []*NodesConfig `mapstructure:"Nodes"`
}

type NodesConfig struct {
	PanelType        string             `mapstructure:"PanelType"`
	ApiConfig        *api.Config        `mapstructure:"ApiConfig"`
	ControllerConfig *controller.Config `mapstructure:"ControllerConfig"`
}

type LogConfig struct {
	Level      string `mapstructure:"Level"`
	AccessPath string `mapstructure:"AccessPath"`
	ErrorPath  string `mapstructure:"ErrorPath"`
}

type ConnectionConfig struct {
	Handshake    uint32 `mapstructure:"handshake"`
	ConnIdle     uint32 `mapstructure:"connIdle"`
	UplinkOnly   uint32 `mapstructure:"uplinkOnly"`
	DownlinkOnly uint32 `mapstructure:"downlinkOnly"`
	BufferSize   int32  `mapstructure:"bufferSize"`
}
