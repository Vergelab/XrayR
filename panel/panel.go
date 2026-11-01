package panel

import (
	"encoding/json"
	"log"
	"os"
	"sync"

	"github.com/Vergelab/XrayR/api/bunpanel"
	"github.com/Vergelab/XrayR/api/gov2panel"
	"github.com/Vergelab/XrayR/api/newV2board"
	"github.com/Vergelab/XrayR/app/mydispatcher"

	"dario.cat/mergo"
	"github.com/r3labs/diff/v2"
	"github.com/xtls/reality"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/Vergelab/XrayR/api"
	"github.com/Vergelab/XrayR/api/pmpanel"
	"github.com/Vergelab/XrayR/api/proxypanel"
	"github.com/Vergelab/XrayR/api/sspanel"
	"github.com/Vergelab/XrayR/api/v2raysocks"
	_ "github.com/Vergelab/XrayR/cmd/distro/all"
	"github.com/Vergelab/XrayR/service"
	"github.com/Vergelab/XrayR/service/controller"
)

// Panel Structure
type Panel struct {
	access      sync.Mutex
	panelConfig *Config
	Server      *core.Instance
	Service     []service.Service
	Running     bool
}

func New(panelConfig *Config) *Panel {
	p := &Panel{panelConfig: panelConfig}
	return p
}

func (p *Panel) loadCore(panelConfig *Config) *core.Instance {
	// Log Config
	coreLogConfig := &conf.LogConfig{}
	logConfig := getDefaultLogConfig()
	if panelConfig.LogConfig != nil {
		if _, err := diff.Merge(logConfig, panelConfig.LogConfig, logConfig); err != nil {
			log.Panicf("Read Log config failed: %s", err)
		}
	}
	coreLogConfig.LogLevel = logConfig.Level
	coreLogConfig.AccessLog = logConfig.AccessPath
	coreLogConfig.ErrorLog = logConfig.ErrorPath

	// DNS config
	coreDnsConfig := &conf.DNSConfig{}
	if panelConfig.DnsConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.DnsConfigPath); err != nil {
			log.Panicf("Failed to read DNS config file at: %s", panelConfig.DnsConfigPath)
		} else {
			if err = json.Unmarshal(data, coreDnsConfig); err != nil {
				log.Panicf("Failed to unmarshal DNS config: %s", panelConfig.DnsConfigPath)
			}
		}
	}

	// init controller's DNS config
	// for _, config := range p.panelConfig.NodesConfig {
	// 	config.ControllerConfig.DNSConfig = coreDnsConfig
	// }

	dnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		log.Panicf("Failed to understand DNS config, Please check: https://xtls.github.io/config/dns.html for help: %s", err)
	}

	// Routing config
	coreRouterConfig := &conf.RouterConfig{}
	if panelConfig.RouteConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.RouteConfigPath); err != nil {
			log.Panicf("Failed to read Routing config file at: %s", panelConfig.RouteConfigPath)
		} else {
			if err = json.Unmarshal(data, coreRouterConfig); err != nil {
				log.Panicf("Failed to unmarshal Routing config: %s", panelConfig.RouteConfigPath)
			}
		}
	}
	routeConfig, err := coreRouterConfig.Build()
	if err != nil {
		log.Panicf("Failed to understand Routing config  Please check: https://xtls.github.io/config/routing.html for help: %s", err)
	}
	// Custom Inbound config
	var coreCustomInboundConfig []conf.InboundDetourConfig
	if panelConfig.InboundConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.InboundConfigPath); err != nil {
			log.Panicf("Failed to read Custom Inbound config file at: %s", panelConfig.InboundConfigPath)
		} else {
			if err = json.Unmarshal(data, &coreCustomInboundConfig); err != nil {
				log.Panicf("Failed to unmarshal Custom Inbound config: %s", panelConfig.InboundConfigPath)
			}
		}
	}
	var inBoundConfig []*core.InboundHandlerConfig
	for _, config := range coreCustomInboundConfig {
		if config.StreamSetting != nil {
			network := ""
			if config.StreamSetting.Network != nil {
				network = string(*config.StreamSetting.Network)
			}
			if config.StreamSetting.KCPSettings != nil {
				if err := controller.ValidateTransportHeader(network, config.StreamSetting.KCPSettings.HeaderConfig); err != nil {
					log.Panicf("Custom inbound: %s", err)
				}
			}
			if config.StreamSetting.TCPSettings != nil {
				if err := controller.ValidateTransportHeader("tcp", config.StreamSetting.TCPSettings.HeaderConfig); err != nil {
					log.Panicf("Custom inbound: %s", err)
				}
			}
		}
		oc, err := config.Build()
		if err != nil {
			log.Panicf("Failed to understand Inbound config, Please check: https://xtls.github.io/config/inbound.html for help: %s", err)
		}
		inBoundConfig = append(inBoundConfig, oc)
	}
	// Custom Outbound config
	var coreCustomOutboundConfig []conf.OutboundDetourConfig
	if panelConfig.OutboundConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.OutboundConfigPath); err != nil {
			log.Panicf("Failed to read Custom Outbound config file at: %s", panelConfig.OutboundConfigPath)
		} else {
			if err = json.Unmarshal(data, &coreCustomOutboundConfig); err != nil {
				log.Panicf("Failed to unmarshal Custom Outbound config: %s", panelConfig.OutboundConfigPath)
			}
		}
	}
	var outBoundConfig []*core.OutboundHandlerConfig
	for _, config := range coreCustomOutboundConfig {
		oc, err := config.Build()
		if err != nil {
			log.Panicf("Failed to understand Outbound config, Please check: https://xtls.github.io/config/outbound.html for help: %s", err)
		}
		outBoundConfig = append(outBoundConfig, oc)
	}
	// Policy config
	levelPolicyConfig := parseConnectionConfig(panelConfig.ConnectionConfig)
	corePolicyConfig := &conf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*conf.Policy{0: levelPolicyConfig}
	policyConfig, _ := corePolicyConfig.Build()
	// Build Core Config
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(coreLogConfig.Build()),
			serial.ToTypedMessage(&mydispatcher.Config{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(policyConfig),
			serial.ToTypedMessage(dnsConfig),
			serial.ToTypedMessage(routeConfig),
		},
		Inbound:  inBoundConfig,
		Outbound: outBoundConfig,
	}
	server, err := core.New(config)
	if err != nil {
		log.Panicf("failed to create instance: %s", err)
	}
	log.Printf("Xray Core Version: %s", core.Version())

	return server
}

// Start the panel
func (p *Panel) Start() {
	p.access.Lock()
	defer p.access.Unlock()
	// Before any listener accepts. Hot reload constructs a new Panel and
	// calls Start again, so the flag follows config.yml. The handshake
	// reads it per connection.
	applyREALITYAllowNonPQ(p.panelConfig)
	log.Print("Start the panel..")
	// Load Core
	server := p.loadCore(p.panelConfig)
	if err := server.Start(); err != nil {
		log.Panicf("Failed to start instance: %s", err)
	}
	p.Server = server

	// Load Nodes config
	for _, nodeConfig := range p.panelConfig.NodesConfig {
		var apiClient api.API
		switch nodeConfig.PanelType {
		case "SSpanel":
			apiClient = sspanel.New(nodeConfig.ApiConfig)
		case "NewV2board", "V2board":
			apiClient = newV2board.New(nodeConfig.ApiConfig)
		case "PMpanel":
			apiClient = pmpanel.New(nodeConfig.ApiConfig)
		case "Proxypanel":
			apiClient = proxypanel.New(nodeConfig.ApiConfig)
		case "V2RaySocks":
			apiClient = v2raysocks.New(nodeConfig.ApiConfig)
		case "GoV2Panel":
			apiClient = gov2panel.New(nodeConfig.ApiConfig)
		case "BunPanel":
			apiClient = bunpanel.New(nodeConfig.ApiConfig)
		default:
			log.Panicf("Unsupport panel type: %s", nodeConfig.PanelType)
		}
		var controllerService service.Service
		// Register controller service
		controllerConfig := mergeControllerConfig(nodeConfig.ControllerConfig)
		controllerService = controller.New(server, apiClient, controllerConfig, nodeConfig.PanelType)
		p.Service = append(p.Service, controllerService)

	}

	// Start all the service
	for _, s := range p.Service {
		err := s.Start()
		if err != nil {
			log.Panicf("Panel Start failed: %s", err)
		}
	}
	p.Running = true
}

// Close the panel
func (p *Panel) Close() {
	p.access.Lock()
	defer p.access.Unlock()
	for _, s := range p.Service {
		err := s.Close()
		if err != nil {
			log.Panicf("Panel Close failed: %s", err)
		}
	}
	p.Service = nil
	p.Server.Close()
	p.Running = false
}

func mergeControllerConfig(node *controller.Config) *controller.Config {
	merged := getDefaultControllerConfig()
	if node != nil {
		if err := mergo.Merge(merged, node, mergo.WithOverride); err != nil {
			log.Panicf("Read Controller Config Failed")
		}
	}
	return merged
}

// resolveREALITYAllowNonPQ chooses the one process-wide value. xray-core's
// REALITY config is a protobuf struct with no per-inbound field, so the
// process can apply only one setting. The top-level key wins when it is
// set. When it is omitted, per-node ControllerConfig.REALITYAllowNonPQClients
// is honored the old way: a nil field is true, the first node wins, and
// mixed is set when a later node disagrees. legacy is set only when the
// top-level key is absent and at least one node still sets the old key.
// differ is set when the top-level key is set and some node's explicit
// value disagrees with it.
func resolveREALITYAllowNonPQ(cfg *Config) (allow bool, legacy bool, mixed bool, differ bool) {
	allow = true
	if cfg != nil && cfg.REALITYAllowNonPQClients != nil {
		allow = *cfg.REALITYAllowNonPQClients
		return allow, false, false, nodesDifferFrom(cfg.NodesConfig, allow)
	}
	var nodes []*NodesConfig
	if cfg != nil {
		nodes = cfg.NodesConfig
	}
	allow, mixed, legacy = resolveLegacyREALITYAllowNonPQ(nodes)
	return allow, legacy, mixed, false
}

// resolveLegacyREALITYAllowNonPQ is the 0.3 per-node rule. explicit reports
// whether any node actually set the deprecated key, as opposed to inheriting
// the default.
func resolveLegacyREALITYAllowNonPQ(nodes []*NodesConfig) (allow bool, mixed bool, explicit bool) {
	allow = true
	seen := false
	for _, node := range nodes {
		var cfg *controller.Config
		if node != nil {
			cfg = node.ControllerConfig
		}
		value := true
		if cfg != nil {
			value = cfg.AllowsNonPQClients()
			if cfg.REALITYAllowNonPQClients != nil {
				explicit = true
			}
		}
		if !seen {
			allow = value
			seen = true
			continue
		}
		if value != allow {
			mixed = true
		}
	}
	return allow, mixed, explicit
}

func nodesDifferFrom(nodes []*NodesConfig, allow bool) bool {
	for _, node := range nodes {
		if node == nil || node.ControllerConfig == nil || node.ControllerConfig.REALITYAllowNonPQClients == nil {
			continue
		}
		if *node.ControllerConfig.REALITYAllowNonPQClients != allow {
			return true
		}
	}
	return false
}

func applyREALITYAllowNonPQ(cfg *Config) {
	allow, legacy, mixed, differ := resolveREALITYAllowNonPQ(cfg)
	switch {
	case legacy && mixed:
		log.Printf("ControllerConfig.REALITYAllowNonPQClients is deprecated and differs across nodes; set top-level REALITYAllowNonPQClients instead. Using the first node's value: %v", allow)
	case legacy:
		log.Printf("ControllerConfig.REALITYAllowNonPQClients is deprecated; set top-level REALITYAllowNonPQClients instead. Using the first node's value: %v", allow)
	case differ:
		log.Printf("top-level REALITYAllowNonPQClients=%v overrides a different ControllerConfig.REALITYAllowNonPQClients; the per-node key is deprecated", allow)
	}
	reality.SetAllowNonPQClients(allow)
}

func parseConnectionConfig(c *ConnectionConfig) (policy *conf.Policy) {
	connectionConfig := getDefaultConnectionConfig()
	if c != nil {
		if _, err := diff.Merge(connectionConfig, c, connectionConfig); err != nil {
			log.Panicf("Read ConnectionConfig failed: %s", err)
		}
	}
	policy = &conf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		Handshake:         &connectionConfig.Handshake,
		ConnectionIdle:    &connectionConfig.ConnIdle,
		UplinkOnly:        &connectionConfig.UplinkOnly,
		DownlinkOnly:      &connectionConfig.DownlinkOnly,
		BufferSize:        &connectionConfig.BufferSize,
	}

	return
}
