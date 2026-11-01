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

	ServerPort FlexInt `json:"server_port"`
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
		ServerPort  FlexString `json:"server_port"`
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

// FlexInt accepts a JSON number or string. Xboard writes the listen port as
// a number; some payloads send it as a string.
type FlexInt int

func (f *FlexInt) UnmarshalJSON(data []byte) error {
	n, err := flexParseInt(data)
	if err != nil {
		return err
	}
	*f = FlexInt(n)
	return nil
}

// FlexString accepts a JSON string or number. tls_settings.server_port is a
// string and may be blank; a numeric port must not fail the whole document.
type FlexString string

func (f *FlexString) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*f = FlexString(strings.TrimSpace(s))
		return nil
	}
	n, err := flexParseInt(data)
	if err != nil {
		return err
	}
	*f = FlexString(strconv.Itoa(n))
	return nil
}

func flexParseInt(data []byte) (int, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return 0, nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return 0, err
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return 0, nil
		}
		return strconv.Atoi(s)
	}
	var n int
	if err := json.Unmarshal(data, &n); err != nil {
		return 0, err
	}
	return n, nil
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
