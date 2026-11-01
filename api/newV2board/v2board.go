package newV2board

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	stdnet "net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/Vergelab/XrayR/api"
)

// APIClient create an api client to the panel.
type APIClient struct {
	client               *resty.Client
	APIHost              string
	NodeID               int
	Key                  string
	NodeType             string
	EnableVless          bool
	VlessFlow            string
	SpeedLimit           float64
	DeviceLimit          int
	LocalRuleList        []api.DetectRule
	resp                 atomic.Value
	eTags                map[string]string
	etagMu               sync.Mutex
	AliveMap             *AliveMap
	aliveMu              sync.Mutex
	pushInterval         atomic.Int64
	alivelistUnsupported sync.Once
}

// New create an api instance
func New(apiConfig *api.Config) *APIClient {
	client := resty.New()
	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		if v, ok := err.(*resty.ResponseError); ok {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})
	client.SetBaseURL(apiConfig.APIHost)

	// Create Key for each requests
	nodeType_for_requests := func() string {
		if apiConfig.NodeType == "V2ray" && apiConfig.EnableVless {
			return "vless"
		} else {
			return apiConfig.NodeType
		}
	}()

	// Xboard 0.1.1-dev (cedar2025/Xboard d73f0decec) checks the token with
	// $request->validate(['token' => required]). Laravel's validate() reads
	// the query string and the body, not a header, so a header-only token is
	// rejected. The token stays a query parameter.
	client.SetQueryParams(map[string]string{
		"node_id":   strconv.Itoa(apiConfig.NodeID),
		"node_type": strings.ToLower(nodeType_for_requests),
		"token":     apiConfig.Key,
	})
	// Read local rule list
	localRuleList := readLocalRuleList(apiConfig.RuleListPath)
	apiClient := &APIClient{
		client:        client,
		NodeID:        apiConfig.NodeID,
		Key:           apiConfig.Key,
		APIHost:       apiConfig.APIHost,
		NodeType:      apiConfig.NodeType,
		EnableVless:   apiConfig.EnableVless,
		VlessFlow:     apiConfig.VlessFlow,
		SpeedLimit:    apiConfig.SpeedLimit,
		DeviceLimit:   apiConfig.DeviceLimit,
		LocalRuleList: localRuleList,
		eTags:         make(map[string]string),
		AliveMap:      &AliveMap{},
	}
	return apiClient
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {
	LocalRuleList = make([]api.DetectRule, 0)

	if path != "" {
		// open the file
		file, err := os.Open(path)
		// handle errors while opening
		if err != nil {
			log.Printf("Error when opening file: %s", err)
			return LocalRuleList
		}
		defer file.Close()
		fileScanner := bufio.NewScanner(file)

		// read line by line
		for fileScanner.Scan() {
			if rule, ok := api.CompileRule(-1, fileScanner.Text()); ok {
				LocalRuleList = append(LocalRuleList, rule)
			}
		}
		if err := fileScanner.Err(); err != nil {
			log.Printf("Error while reading file: %s", err)
			return
		}
	}

	return LocalRuleList
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key, NodeType: c.NodeType}
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*simplejson.Json, error) {
	if nerr := api.NilResponse(res, err); nerr != nil {
		return nil, fmt.Errorf("request %s failed: %w", c.assembleURL(path), nerr)
	}
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %v", c.assembleURL(path), err)
	}

	if res.StatusCode() > 399 {
		return nil, fmt.Errorf("request %s failed: %s, %v", c.assembleURL(path), res.String(), err)
	}

	rtn, err := simplejson.NewJson(res.Body())
	if err != nil {
		return nil, fmt.Errorf("ret %s invalid", res.String())
	}

	return rtn, nil
}

// GetNodeInfo will pull NodeInfo Config from panel
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	server := new(serverConfig)
	path := "/api/v1/server/UniProxy/config"

	c.etagMu.Lock()
	nodeETag := c.eTags["node"]
	c.etagMu.Unlock()
	res, err := c.client.R().
		SetHeader("If-None-Match", nodeETag).
		ForceContentType("application/json").
		Get(path)
	if nerr := api.NilResponse(res, err); nerr != nil {
		return nil, fmt.Errorf("request %s failed: %w", c.assembleURL(path), nerr)
	}

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.NodeNotModified)
	}

	nodeInfoResp, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	b, err := nodeInfoResp.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode node info failed: %w", err)
	}
	if err := json.Unmarshal(b, server); err != nil {
		return nil, fmt.Errorf("parse node info failed: %s: %w", redactPanelBody(b), err)
	}

	if server.ServerPort == 0 {
		return nil, errors.New("server port must > 0")
	}
	c.resp.Store(server)

	switch c.NodeType {
	case "V2ray", "Vmess", "Vless":
		nodeInfo, err = c.parseV2rayNodeResponse(server)
	case "Trojan":
		nodeInfo, err = c.parseTrojanNodeResponse(server)
	case "Shadowsocks":
		nodeInfo, err = c.parseSSNodeResponse(server)
	default:
		return nil, fmt.Errorf("unsupported node type: %s", c.NodeType)
	}

	if err != nil {
		return nil, fmt.Errorf("parse node info failed: %s, \nError: %v", redactPanelBody(res.Body()), err)
	}
	if etag := res.Header().Get("Etag"); etag != "" {
		c.etagMu.Lock()
		c.eTags["node"] = etag
		c.etagMu.Unlock()
	}
	if server.BaseConfig.PushInterval > 0 {
		c.pushInterval.Store(int64(server.BaseConfig.PushInterval))
	}

	return nodeInfo, nil
}

// GetUserList will pull user form panel
func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	path := "/api/v1/server/UniProxy/user"

	switch c.NodeType {
	case "V2ray", "Trojan", "Shadowsocks", "Vmess", "Vless":
		break
	default:
		return nil, fmt.Errorf("unsupported node type: %s", c.NodeType)
	}

	c.etagMu.Lock()
	userETag := c.eTags["users"]
	c.etagMu.Unlock()
	res, err := c.client.R().
		SetHeader("If-None-Match", userETag).
		ForceContentType("application/json").
		Get(path)

	if _, aliveErr := c.GetUserAlive(); aliveErr != nil {
		log.Printf("user alive list: %v", aliveErr)
	}

	if nerr := api.NilResponse(res, err); nerr != nil {
		return nil, fmt.Errorf("request %s failed: %w", c.assembleURL(path), nerr)
	}
	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.UserNotModified)
	}

	usersResp, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	b, err := usersResp.Get("users").Encode()
	if err != nil {
		return nil, fmt.Errorf("encode user list failed: %w", err)
	}
	userList, err := c.usersFromJSON(b)
	if err != nil {
		return nil, err
	}
	if etag := res.Header().Get("Etag"); etag != "" {
		c.etagMu.Lock()
		c.eTags["users"] = etag
		c.etagMu.Unlock()
	}
	return userList, nil
}

// usersFromJSON accepts a user array, JSON null, or an empty array.
// null and [] both mean "no users", which removes every user on the node.
func (c *APIClient) usersFromJSON(raw []byte) (*[]api.UserInfo, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" || trimmed == "[]" {
		empty := make([]api.UserInfo, 0)
		return &empty, nil
	}
	var users []*user
	if err := json.Unmarshal(raw, &users); err != nil {
		return nil, fmt.Errorf("parse user list failed: %w", err)
	}
	if len(users) == 0 {
		empty := make([]api.UserInfo, 0)
		return &empty, nil
	}

	var deviceLimit int = 0
	var userList []api.UserInfo
	for _, user := range users {
		u := api.UserInfo{
			UID:  user.Id,
			UUID: user.Uuid,
		}
		// Support 1.7.1 speed limit
		if c.SpeedLimit > 0 {
			u.SpeedLimit = uint64(c.SpeedLimit * 1000000 / 8)
		} else {
			u.SpeedLimit = uint64(user.SpeedLimit * 1000000 / 8)
		}
		//Prefer local config
		if c.DeviceLimit > 0 {
			deviceLimit = c.DeviceLimit
		} else {
			deviceLimit = user.DeviceLimit
		}

		u.DeviceLimit = deviceLimit
		u.Email = u.UUID + "@v2board.user"
		if c.NodeType == "Shadowsocks" {
			u.Passwd = u.UUID
		}

		userList = append(userList, u)
	}
	return &userList, nil
}

// PushInterval is the panel base_config.push_interval in seconds, or 0 when
// the panel did not send one.
func (c *APIClient) PushInterval() int {
	return int(c.pushInterval.Load())
}

// AliveSnapshot copies the last successful alive map. A failed poll does not
// clear it.
func (c *APIClient) AliveSnapshot() map[int]int {
	c.aliveMu.Lock()
	defer c.aliveMu.Unlock()
	if c.AliveMap == nil || c.AliveMap.Alive == nil {
		return map[int]int{}
	}
	cp := make(map[int]int, len(c.AliveMap.Alive))
	for k, v := range c.AliveMap.Alive {
		cp[k] = v
	}
	return cp
}

// InvalidateNodeETag forces the next config poll to ignore 304. Call this
// when a parsed config could not be applied, so the next poll retries it.
func (c *APIClient) InvalidateNodeETag() {
	c.etagMu.Lock()
	delete(c.eTags, "node")
	c.etagMu.Unlock()
}

// GetUserAlive will fetch the alive_ip count for users.
// A 404 means this panel has no alivelist; that is logged once and the last
// good map is kept. Any other failure is logged by the caller and also keeps
// the last good map.
func (c *APIClient) GetUserAlive() (map[int]int, error) {
	const path = "/api/v1/server/UniProxy/alivelist"
	r, err := c.client.R().
		ForceContentType("application/json").
		Get(path)
	if nerr := api.NilResponse(r, err); nerr != nil {
		return c.AliveSnapshot(), fmt.Errorf("alivelist request failed: %w", nerr)
	}
	if r.StatusCode() == 404 {
		c.alivelistUnsupported.Do(func() {
			log.Printf("panel alivelist returned 404; device limits use local IPs only")
		})
		return c.AliveSnapshot(), nil
	}
	if err != nil || r.StatusCode() > 399 {
		if err == nil {
			err = fmt.Errorf("alivelist status %d", r.StatusCode())
		}
		return c.AliveSnapshot(), err
	}
	parsed := &AliveMap{}
	if err := json.Unmarshal(r.Body(), parsed); err != nil {
		return c.AliveSnapshot(), fmt.Errorf("unmarshal user alive list error: %s", err)
	}
	if parsed.Alive == nil {
		parsed.Alive = map[int]int{}
	}
	c.aliveMu.Lock()
	c.AliveMap = parsed
	c.aliveMu.Unlock()
	return c.AliveSnapshot(), nil
}

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {
	path := "/api/v1/server/UniProxy/push"

	// json structure: {uid1: [u, d], uid2: [u, d], uid1: [u, d], uid3: [u, d]}
	data := make(map[int][]int64, len(*userTraffic))
	for _, traffic := range *userTraffic {
		data[traffic.UID] = []int64{traffic.Upload, traffic.Download}
	}

	res, err := c.client.R().SetBody(data).ForceContentType("application/json").Post(path)
	parsed, err := c.parseResponse(res, path, err)
	if err != nil {
		return err
	}
	body, err := parsed.Encode()
	if err != nil {
		return fmt.Errorf("encode push response: %w", err)
	}
	if err := panelBodyStatus(body); err != nil {
		return fmt.Errorf("push rejected: %w", err)
	}
	return nil
}

// GetNodeRule implements the API interface
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	routes := c.resp.Load().(*serverConfig).Routes

	ruleList := c.LocalRuleList

	for i := range routes {
		if routes[i].Action == "block" {
			if rule, ok := api.CompileRule(i, strings.Join(routes[i].Match, "|")); ok {
				ruleList = append(ruleList, rule)
			}
		}
	}

	return &ruleList, nil
}

// ReportNodeStatus implements the API interface
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	return nil
}

// ReportNodeOnlineUsers implements the API interface
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	data := make(map[int][]string)
	for _, onlineuser := range *onlineUserList {
		// json structure: { UID1:["ip1","ip2"],UID2:["ip3","ip4"] }
		data[onlineuser.UID] = append(data[onlineuser.UID], onlineuser.IP)
	}

	path := "/api/v1/server/UniProxy/alive"
	res, err := c.client.R().SetBody(data).ForceContentType("application/json").Post(path)
	parsed, err := c.parseResponse(res, path, err)
	if err != nil {
		return err
	}
	body, err := parsed.Encode()
	if err != nil {
		return fmt.Errorf("encode alive response: %w", err)
	}
	if err := panelBodyStatus(body); err != nil {
		return fmt.Errorf("alive rejected: %w", err)
	}
	return nil
}

// ReportIllegal implements the API interface
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	return nil
}

// parseTrojanNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) parseTrojanNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	var (
		host   string
		header json.RawMessage
	)
	transportProtocol := func() string {
		if s.Network == "" {
			return "tcp"
		} else {
			return s.Network
		}
	}()
	switch transportProtocol {
	case "ws":
		if s.NetworkSettings.Headers != nil {
			if httpHeader, err := s.NetworkSettings.Headers.MarshalJSON(); err != nil {
				return nil, err
			} else {
				b, _ := simplejson.NewJson(httpHeader)
				host = b.Get("Host").MustString()
			}
		}
	case "tcp":
		if s.NetworkSettings.Header != nil {
			if httpHeader, err := s.NetworkSettings.Header.MarshalJSON(); err != nil {
				return nil, err
			} else {
				header = httpHeader
			}
		}
	}
	// Create GeneralNodeInfo
	nodeInfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(s.ServerPort),
		TransportProtocol: transportProtocol,
		Path:              s.NetworkSettings.Path,
		EnableTLS:         true,
		Host:              host,
		Header:            header,
		ServiceName:       s.NetworkSettings.ServiceName,
		NameServerConfig:  s.parseDNSConfig(),
	}
	return nodeInfo, nil
}

// parseSSNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) parseSSNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	var header json.RawMessage

	if s.Obfs == "http" {
		path := "/"
		if p := s.ObfsSettings.Path; p != "" {
			if strings.HasPrefix(p, "/") {
				path = p
			} else {
				path += p
			}
		}
		h := simplejson.New()
		h.Set("type", "http")
		h.SetPath([]string{"request", "path"}, path)
		header, _ = h.Encode()
	}
	// Create GeneralNodeInfo
	return &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(s.ServerPort),
		TransportProtocol: "tcp",
		CypherMethod:      s.Cipher,
		ServerKey:         s.ServerKey, // shadowsocks2022 share key
		NameServerConfig:  s.parseDNSConfig(),
		Header:            header,
	}, nil
}

// parseV2rayNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) parseV2rayNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	var (
		host          string
		header        json.RawMessage
		enableTLS     bool
		enableREALITY bool
		dest          string
	)
	if s.TlsSettings.Dest != "" {
		dest = s.TlsSettings.Dest
	} else {
		dest = s.TlsSettings.Sni
	}
	realityDest, err := realityDestFromPanel(dest, string(s.TlsSettings.ServerPort))
	if err != nil && s.Tls == 2 {
		return nil, err
	}
	if realityDest == "" {
		realityDest = dest
	}
	mldsaSeed := s.TlsSettings.Mldsa65Seed
	if mldsaSeed == "" {
		mldsaSeed = s.TlsSettings.Mldsa65
	}
	realityconfig := api.REALITYConfig{
		Dest:             realityDest,
		ProxyProtocolVer: uint64(s.TlsSettings.Xver),
		ServerNames:      []string{s.TlsSettings.Sni},
		PrivateKey:       s.TlsSettings.PrivateKey,
		ShortIds:         []string{s.TlsSettings.ShortId},
		Mldsa65Seed:      mldsaSeed,
	}
	switch s.Network {
	case "ws":
		if s.NetworkSettings.Headers != nil {
			if httpHeader, err := s.NetworkSettings.Headers.MarshalJSON(); err != nil {
				return nil, err
			} else {
				b, _ := simplejson.NewJson(httpHeader)
				host = b.Get("Host").MustString()
			}
		}
	case "tcp":
		if s.NetworkSettings.Header != nil {
			if httpHeader, err := s.NetworkSettings.Header.MarshalJSON(); err != nil {
				return nil, err
			} else {
				header = httpHeader
			}
		}
	case "httpupgrade", "xhttp":
		if s.NetworkSettings.Headers != nil {
			if httpHeaders, err := s.NetworkSettings.Headers.MarshalJSON(); err != nil {
				return nil, err
			} else {
				b, _ := simplejson.NewJson(httpHeaders)
				host = b.Get("Host").MustString()
			}
		}
		if s.NetworkSettings.Host != "" {
			host = s.NetworkSettings.Host
		}
	}

	if s.Tls != 0 {
		enableTLS = true
		if s.Tls == 2 {
			enableREALITY = true
		}
	}

	flow := strings.TrimSpace(s.VlessFlow)
	if flow == "" {
		flow = strings.TrimSpace(c.VlessFlow)
	}

	// Create GeneralNodeInfo
	return &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(s.ServerPort),
		AlterID:           0,
		TransportProtocol: s.Network,
		EnableTLS:         enableTLS,
		Path:              s.NetworkSettings.Path,
		Host:              host,
		EnableVless:       c.EnableVless,
		VlessFlow:         flow,
		ServiceName:       s.NetworkSettings.ServiceName,
		Header:            header,
		EnableREALITY:     enableREALITY,
		REALITYConfig:     &realityconfig,
		NameServerConfig:  s.parseDNSConfig(),
	}, nil
}

// realityDestFromPanel keeps an explicit host:port dest and otherwise appends
// server_port, defaulting a blank port to 443 so dest is never "sni:".
func realityDestFromPanel(dest, serverPort string) (string, error) {
	dest = strings.TrimSpace(dest)
	port := strings.TrimSpace(serverPort)
	if port == "" {
		port = "443"
	}
	if dest == "" {
		return "", fmt.Errorf("REALITY dest is empty: server_name and dest are both blank")
	}
	if host, existingPort, err := stdnet.SplitHostPort(dest); err == nil {
		if existingPort != "" {
			// dest already has a port. Do not append server_port again:
			// "www.example.com:443" + ":8443" is not a valid REALITY target.
			return dest, nil
		}
		if host == "" {
			return "", fmt.Errorf("REALITY dest %q is invalid", dest)
		}
		return stdnet.JoinHostPort(host, port), nil
	}
	// SplitHostPort failed. A bare IPv6 address ("2001:db8::1") and a
	// bracketed one with no port ("[2001:db8::1]") both land here.
	// JoinHostPort wraps a host that contains ':' in brackets, so a value
	// that is already bracketed must be unwrapped first or the target
	// becomes "[[2001:db8::1]]:443".
	host := dest
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' && strings.Contains(host, ":") {
		host = host[1 : len(host)-1]
	}
	return stdnet.JoinHostPort(host, port), nil
}

// panelBodyStatus fails the call when the JSON body carries a status that
// is not success. Bodies without a status field are accepted: HTTP status
// was already checked. Xboard 0.1.1 returns {"status":"success",...} after
// queueing TrafficFetchJob; a queued 200 is still success here, and bytes
// are put back only when this check or the HTTP status fails.
func panelBodyStatus(body []byte) error {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil
	}
	var probe map[string]any
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil
	}
	status, ok := probe["status"]
	if !ok || status == nil {
		return nil
	}
	switch s := status.(type) {
	case string:
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "success", "ok", "true":
			return nil
		default:
			return fmt.Errorf("panel status %q", s)
		}
	case bool:
		if s {
			return nil
		}
		return fmt.Errorf("panel status false")
	default:
		return fmt.Errorf("panel status %v", s)
	}
}

var privateKeyRE = regexp.MustCompile(`(?i)("private_key"\s*:\s*")([^"]*)(")`)

func redactPanelBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return privateKeyRE.ReplaceAllString(string(body), `${1}[redacted]${3}`)
	}
	redactSecrets(v)
	out, err := json.Marshal(v)
	if err != nil {
		return "[redacted]"
	}
	return string(out)
}

func redactSecrets(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if strings.EqualFold(k, "private_key") {
				t[k] = "[redacted]"
				continue
			}
			redactSecrets(val)
		}
	case []any:
		for _, item := range t {
			redactSecrets(item)
		}
	}
}

func (s *serverConfig) parseDNSConfig() (nameServerList []*conf.NameServerConfig) {
	for i := range s.Routes {
		if s.Routes[i].Action == "dns" {
			nameServerList = append(nameServerList, &conf.NameServerConfig{
				Address: &conf.Address{Address: net.ParseAddress(s.Routes[i].ActionValue)},
				Domains: s.Routes[i].Match,
			})
		}
	}

	return
}
