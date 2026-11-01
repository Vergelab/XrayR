package newV2board

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

type serverConfig struct {
	shadowsocks
	v2ray
	trojan

	ServerPort int `json:"server_port"`
	BaseConfig struct {
		PushInterval int `json:"push_interval"`
		PullInterval int `json:"pull_interval"`
	} `json:"base_config"`
	Routes []route `json:"routes"`
}

type shadowsocks struct {
	Cipher       string `json:"cipher"`
	Obfs         string `json:"obfs"`
	ObfsSettings struct {
		Path string `json:"path"`
		Host string `json:"host"`
	} `json:"obfs_settings"`
	ServerKey string `json:"server_key"`
}

type v2ray struct {
	Network         string `json:"network"`
	NetworkSettings struct {
		Path        string           `json:"path"`
		Host        string           `json:"host"`
		Headers     *json.RawMessage `json:"headers"`
		ServiceName string           `json:"serviceName"`
		Header      *json.RawMessage `json:"header"`
	} `json:"networkSettings"`
	VlessFlow   string `json:"flow"`
	TlsSettings struct {
		ServerPort  string     `json:"server_port"`
		Dest        string     `json:"dest"`
		Xver        FlexUint64 `json:"xver"`
		Sni         string     `json:"server_name"`
		PrivateKey  string     `json:"private_key"`
		ShortId     string     `json:"short_id"`
		Mldsa65Seed string     `json:"mldsa65Seed"`
		Mldsa65     string     `json:"mldsa65"`
	} `json:"tls_settings"`
	Tls int `json:"tls"`
}

type trojan struct {
	Host       string `json:"host"`
	ServerName string `json:"server_name"`
}

type route struct {
	Id          int      `json:"id"`
	Match       []string `json:"match"`
	Action      string   `json:"action"`
	ActionValue string   `json:"action_value"`
}

type user struct {
	Id          int    `json:"id"`
	Uuid        string `json:"uuid"`
	SpeedLimit  int    `json:"speed_limit"`
	DeviceLimit int    `json:"device_limit"`
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

// FlexUint64 accepts a JSON number or string. Older panels omit xver; some
// send it as a number and some as a string.
type FlexUint64 uint64

func (f *FlexUint64) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return nil
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return err
		}
		*f = FlexUint64(n)
		return nil
	}
	var n uint64
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	*f = FlexUint64(n)
	return nil
}
