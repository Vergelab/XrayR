package controller

import (
	"github.com/Vergelab/XrayR/common/limiter"
	"github.com/Vergelab/XrayR/common/mylego"
)

type Config struct {
	ListenIP                  string                           `mapstructure:"ListenIP"`
	SendIP                    string                           `mapstructure:"SendIP"`
	UpdatePeriodic            int                              `mapstructure:"UpdatePeriodic"`
	DeviceOnlineMinTraffic    int                              `mapstructure:"DeviceOnlineMinTraffic"`
	CertConfig                *mylego.CertConfig               `mapstructure:"CertConfig"`
	EnableDNS                 bool                             `mapstructure:"EnableDNS"`
	DNSType                   string                           `mapstructure:"DNSType"`
	DisableUploadTraffic      bool                             `mapstructure:"DisableUploadTraffic"`
	DisableGetRule            bool                             `mapstructure:"DisableGetRule"`
	EnableProxyProtocol       bool                             `mapstructure:"EnableProxyProtocol"`
	EnableFallback            bool                             `mapstructure:"EnableFallback"`
	DisableIVCheck            bool                             `mapstructure:"DisableIVCheck"` // Ignored. xray-core v26 removed Shadowsocks IV replay checks.
	DisableSniffing           bool                             `mapstructure:"DisableSniffing"`
	AutoSpeedLimitConfig      *AutoSpeedLimitConfig            `mapstructure:"AutoSpeedLimitConfig"`
	GlobalDeviceLimitConfig   *limiter.GlobalDeviceLimitConfig `mapstructure:"GlobalDeviceLimitConfig"`
	FallBackConfigs           []*FallBackConfig                `mapstructure:"FallBackConfigs"`
	DisableLocalREALITYConfig bool                             `mapstructure:"DisableLocalREALITYConfig"`
	EnableREALITY             bool                             `mapstructure:"EnableREALITY"`
	REALITYConfigs            *REALITYConfig                   `mapstructure:"REALITYConfigs"`
	// REALITYAllowNonPQClients is deprecated. Set the top-level
	// REALITYAllowNonPQClients key instead. Still parsed so old configs load.
	// When the top-level key is omitted, the first node's value wins
	// (nil means true) and a deprecation warning is logged.
	REALITYAllowNonPQClients *bool `mapstructure:"REALITYAllowNonPQClients"`
}

// AllowsNonPQClients reports whether this node accepts X25519-only REALITY
// ClientHellos. A nil config or a nil field is the default, true.
func (c *Config) AllowsNonPQClients() bool {
	if c == nil || c.REALITYAllowNonPQClients == nil {
		return true
	}
	return *c.REALITYAllowNonPQClients
}

type AutoSpeedLimitConfig struct {
	Limit         int `mapstructure:"Limit"` // mbps
	WarnTimes     int `mapstructure:"WarnTimes"`
	LimitSpeed    int `mapstructure:"LimitSpeed"`    // mbps
	LimitDuration int `mapstructure:"LimitDuration"` // minute
}

type FallBackConfig struct {
	SNI              string `mapstructure:"SNI"`
	Alpn             string `mapstructure:"Alpn"`
	Path             string `mapstructure:"Path"`
	Dest             string `mapstructure:"Dest"`
	ProxyProtocolVer uint64 `mapstructure:"ProxyProtocolVer"`
}

type REALITYConfig struct {
	Show             bool     `mapstructure:"Show"`
	Dest             string   `mapstructure:"Dest"`
	ProxyProtocolVer uint64   `mapstructure:"ProxyProtocolVer"`
	ServerNames      []string `mapstructure:"ServerNames"`
	PrivateKey       string   `mapstructure:"PrivateKey"`
	MinClientVer     string   `mapstructure:"MinClientVer"`
	MaxClientVer     string   `mapstructure:"MaxClientVer"`
	MaxTimeDiff      uint64   `mapstructure:"MaxTimeDiff"`
	ShortIds         []string `mapstructure:"ShortIds"`
	Mldsa65Seed      string   `mapstructure:"Mldsa65Seed"` // Optional. Clients still use X25519MLKEM768.
}
