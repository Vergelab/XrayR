package controller

import (
	"errors"
	"fmt"
	"reflect"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"

	"github.com/Vergelab/XrayR/api"
	"github.com/Vergelab/XrayR/api/newV2board"
	"github.com/Vergelab/XrayR/app/mydispatcher"
	"github.com/Vergelab/XrayR/common/limiter"
	"github.com/Vergelab/XrayR/common/mylego"
	"github.com/Vergelab/XrayR/common/serverstatus"
)

type LimitInfo struct {
	end               int64
	currentSpeedLimit int
	originSpeedLimit  uint64
}

type Controller struct {
	mu              sync.RWMutex
	server          *core.Instance
	config          *Config
	clientInfo      api.ClientInfo
	apiClient       api.API
	nodeInfo        *api.NodeInfo
	Tag             string
	userList        *[]api.UserInfo
	tasks           []periodicTask
	limitedUsers    map[api.UserInfo]LimitInfo
	warnedUsers     map[api.UserInfo]int
	panelType       string
	ibm             inbound.Manager
	obm             outbound.Manager
	stm             stats.Manager
	dispatcher      *mydispatcher.DefaultDispatcher
	startAt         time.Time
	logger          *log.Entry
	trafficInterval atomic.Int64
}

// New return a Controller service with default parameters.
func New(server *core.Instance, api api.API, config *Config, panelType string) *Controller {
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": api.Describe().APIHost,
		"Type": api.Describe().NodeType,
		"ID":   api.Describe().NodeID,
	})
	controller := &Controller{
		server:     server,
		config:     config,
		apiClient:  api,
		panelType:  panelType,
		ibm:        server.GetFeature(inbound.ManagerType()).(inbound.Manager),
		obm:        server.GetFeature(outbound.ManagerType()).(outbound.Manager),
		stm:        server.GetFeature(stats.ManagerType()).(stats.Manager),
		dispatcher: server.GetFeature(routing.DispatcherType()).(*mydispatcher.DefaultDispatcher),
		startAt:    time.Now(),
		logger:     logger,
	}

	return controller
}

// Start implement the Start() function of the service interface
func (c *Controller) Start() error {
	c.clientInfo = c.apiClient.Describe()
	// First fetch Node Info
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		return err
	}
	if newNodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	c.notePushInterval()
	if newNodeInfo.EnableVless || newNodeInfo.NodeType == "Vless" {
		c.logger.Infof("effective VLESS flow: %s", newNodeInfo.VlessFlow)
	}
	c.mu.Lock()
	c.nodeInfo = newNodeInfo
	c.Tag = fmt.Sprintf("%s_%s_%d", newNodeInfo.NodeType, c.config.ListenIP, newNodeInfo.Port)
	c.mu.Unlock()

	// Add new tag
	err = c.addNewTag(newNodeInfo)
	if err != nil {
		c.logger.Panic(err)
		return err
	}
	// Update user
	userInfo, err := c.apiClient.GetUserList()
	if err != nil {
		return err
	}

	// sync controller userList
	c.mu.Lock()
	c.userList = userInfo
	c.mu.Unlock()

	err = c.addNewUser(userInfo, newNodeInfo)
	if err != nil {
		return err
	}

	// Add Limiter
	if err := c.AddInboundLimiter(c.Tag, newNodeInfo.SpeedLimit, userInfo, c.config.GlobalDeviceLimitConfig); err != nil {
		c.logger.Print(err)
	}
	c.syncAlive()

	// Add Rule Manager
	if !c.config.DisableGetRule {
		if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
			c.logger.Printf("Get rule list filed: %s", err)
		} else if len(*ruleList) > 0 {
			if err := c.UpdateRule(c.Tag, *ruleList); err != nil {
				c.logger.Print(err)
			}
		}
	}

	// Init AutoSpeedLimitConfig
	if c.config.AutoSpeedLimitConfig == nil {
		c.config.AutoSpeedLimitConfig = &AutoSpeedLimitConfig{0, 0, 0, 0}
	}
	if c.config.AutoSpeedLimitConfig.Limit > 0 {
		c.limitedUsers = make(map[api.UserInfo]LimitInfo)
		c.warnedUsers = make(map[api.UserInfo]int)
	}

	// Add periodic tasks. push_interval, when the panel sends it, replaces
	// UpdatePeriodic for the traffic task only.
	c.tasks = append(c.tasks,
		periodicTask{
			tag:      "node monitor",
			interval: c.nodeInterval,
			execute:  c.guard("node monitor", c.nodeInfoMonitor),
			stop:     make(chan struct{}),
		},
		periodicTask{
			tag:      "user monitor",
			interval: c.userInterval,
			execute:  c.guard("user monitor", c.userInfoMonitor),
			stop:     make(chan struct{}),
		},
	)

	if c.needsCertMonitor() {
		c.tasks = append(c.tasks, periodicTask{
			tag: "cert monitor",
			interval: func() time.Duration {
				return c.nodeInterval() * 60
			},
			execute: c.guard("cert monitor", c.certMonitor),
			stop:    make(chan struct{}),
		})
	}

	// Start periodic tasks
	for i := range c.tasks {
		c.logger.Printf("Start %s periodic task", c.tasks[i].tag)
		go c.tasks[i].Start()
	}

	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	for i := range c.tasks {
		if err := c.tasks[i].Close(); err != nil {
			c.logger.Printf("%s periodic task close failed: %s", c.tasks[i].tag, err)
		}
	}
	return nil
}

func (c *Controller) guard(tag string, fn func() error) func() error {
	return func() error {
		defer func() {
			if recovered := recover(); recovered != nil {
				c.logger.Printf("%s periodic task recovered from panic: %v\n%s", tag, recovered, debug.Stack())
			}
		}()
		return fn()
	}
}

func (c *Controller) nodeInterval() time.Duration {
	sec := c.config.UpdatePeriodic
	if sec <= 0 {
		sec = 60
	}
	return time.Duration(sec) * time.Second
}

func (c *Controller) userInterval() time.Duration {
	if pi := c.trafficInterval.Load(); pi > 0 {
		return time.Duration(pi) * time.Second
	}
	return c.nodeInterval()
}

func (c *Controller) notePushInterval() {
	v2b, ok := c.apiClient.(*newV2board.APIClient)
	if !ok {
		return
	}
	if pi := v2b.PushInterval(); pi > 0 {
		c.trafficInterval.Store(int64(pi))
	}
}

func (c *Controller) syncAlive() {
	v2b, ok := c.apiClient.(*newV2board.APIClient)
	if !ok {
		return
	}
	c.mu.RLock()
	tag := c.Tag
	c.mu.RUnlock()
	if v, ok := c.dispatcher.Limiter.InboundInfo.Load(tag); ok {
		v.(*limiter.InboundInfo).SetAliveList(v2b.AliveSnapshot())
	}
}

func (c *Controller) needsCertMonitor() bool {
	c.mu.RLock()
	info := c.nodeInfo
	c.mu.RUnlock()
	if info == nil || !info.EnableTLS || info.EnableREALITY || c.config.EnableREALITY {
		return false
	}
	if c.config.CertConfig == nil {
		return false
	}
	switch c.config.CertConfig.CertMode {
	case "dns", "http", "tls":
		return true
	default:
		return false
	}
}

func (c *Controller) nodeInfoMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < c.nodeInterval() {
		return nil
	}

	c.mu.RLock()
	currentNode := c.nodeInfo
	currentTag := c.Tag
	currentUsers := c.userList
	c.mu.RUnlock()

	// First fetch Node Info
	var nodeInfoChanged = true
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		if err.Error() == api.NodeNotModified {
			nodeInfoChanged = false
			newNodeInfo = currentNode
		} else {
			c.logger.Print(err)
			return nil
		}
	}
	if newNodeInfo == nil || newNodeInfo.Port == 0 {
		c.logger.Print("server port must > 0")
		return nil
	}
	c.notePushInterval()

	// Update User
	var usersChanged = true
	newUserInfo, err := c.apiClient.GetUserList()
	c.syncAlive()
	if err != nil {
		if err.Error() == api.UserNotModified {
			usersChanged = false
			newUserInfo = currentUsers
		} else if err.Error() == "users is null" {
			empty := make([]api.UserInfo, 0)
			newUserInfo = &empty
		} else {
			c.logger.Print(err)
			return nil
		}
	}
	if newUserInfo == nil {
		empty := make([]api.UserInfo, 0)
		newUserInfo = &empty
	}

	// If nodeInfo changed, build the new inbound first. A failed build keeps
	// the old inbound and does not record the new nodeInfo, so the next poll
	// tries again. User changes still apply to the inbound that is serving.
	applied := false
	if nodeInfoChanged && !reflect.DeepEqual(currentNode, newNodeInfo) {
		oldTag := currentTag
		if err := c.replaceNode(currentNode, currentTag, newNodeInfo); err != nil {
			c.logger.Print(err)
			if v2b, ok := c.apiClient.(*newV2board.APIClient); ok {
				v2b.InvalidateNodeETag()
			}
		} else {
			if err = c.DeleteInboundLimiter(oldTag); err != nil {
				c.logger.Print(err)
			}
			c.mu.RLock()
			currentTag = c.Tag
			currentNode = c.nodeInfo
			c.mu.RUnlock()
			applied = true
			if newNodeInfo.EnableVless || newNodeInfo.NodeType == "Vless" {
				c.logger.Infof("effective VLESS flow: %s", newNodeInfo.VlessFlow)
			}
		}
	}

	// Check Rule
	if !c.config.DisableGetRule {
		if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
			if err.Error() != api.RuleNotModified {
				c.logger.Printf("Get rule list filed: %s", err)
			}
		} else if ruleList != nil && len(*ruleList) > 0 {
			if err := c.UpdateRule(currentTag, *ruleList); err != nil {
				c.logger.Print(err)
			}
		}
	}

	if applied {
		err = c.addNewUser(newUserInfo, newNodeInfo)
		if err != nil {
			c.logger.Print(err)
			return nil
		}
		if err := c.AddInboundLimiter(currentTag, newNodeInfo.SpeedLimit, newUserInfo, c.config.GlobalDeviceLimitConfig); err != nil {
			c.logger.Print(err)
			return nil
		}
		c.syncAlive()
	} else {
		var deleted, added []api.UserInfo
		if usersChanged {
			deleted, added = compareUserList(currentUsers, newUserInfo)
			if len(deleted) > 0 {
				deletedEmail := make([]string, len(deleted))
				for i, u := range deleted {
					deletedEmail[i] = fmt.Sprintf("%s|%s|%d", currentTag, u.Email, u.UID)
				}
				err := c.removeUsers(deletedEmail, currentTag)
				if err != nil {
					c.logger.Print(err)
				}
			}
			if len(added) > 0 {
				err = c.addNewUser(&added, currentNode)
				if err != nil {
					c.logger.Print(err)
				}
				if err := c.UpdateInboundLimiter(currentTag, &added); err != nil {
					c.logger.Print(err)
				}
			}
		}
		c.logger.Printf("%d user deleted, %d user added", len(deleted), len(added))
	}
	c.mu.Lock()
	c.userList = newUserInfo
	c.mu.Unlock()
	return nil
}

func (c *Controller) removeOldTag(oldTag string) (err error) {
	err = c.removeInbound(oldTag)
	if err != nil {
		return err
	}
	err = c.removeOutbound(oldTag)
	if err != nil {
		return err
	}
	return nil
}

func (c *Controller) addNewTag(newNodeInfo *api.NodeInfo) (err error) {
	if newNodeInfo.NodeType != "Shadowsocks-Plugin" {
		inboundConfig, err := InboundBuilder(c.config, newNodeInfo, c.Tag)
		if err != nil {
			return err
		}
		err = c.addInbound(inboundConfig)
		if err != nil {

			return err
		}
		outBoundConfig, err := OutboundBuilder(c.config, newNodeInfo, c.Tag)
		if err != nil {

			return err
		}
		err = c.addOutbound(outBoundConfig)
		if err != nil {

			return err
		}

	} else {
		return c.addInboundForSSPlugin(*newNodeInfo)
	}
	return nil
}

func (c *Controller) addInboundForSSPlugin(newNodeInfo api.NodeInfo) (err error) {
	// Shadowsocks-Plugin require a separate inbound for other TransportProtocol likes: ws, grpc
	fakeNodeInfo := newNodeInfo
	fakeNodeInfo.TransportProtocol = "tcp"
	fakeNodeInfo.EnableTLS = false
	// Add a regular Shadowsocks inbound and outbound
	inboundConfig, err := InboundBuilder(c.config, &fakeNodeInfo, c.Tag)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {

		return err
	}
	outBoundConfig, err := OutboundBuilder(c.config, &fakeNodeInfo, c.Tag)
	if err != nil {

		return err
	}
	err = c.addOutbound(outBoundConfig)
	if err != nil {

		return err
	}
	// Add an inbound for upper streaming protocol
	fakeNodeInfo = newNodeInfo
	fakeNodeInfo.Port++
	fakeNodeInfo.NodeType = "dokodemo-door"
	dokodemoTag := fmt.Sprintf("dokodemo-door_%s+1", c.Tag)
	inboundConfig, err = InboundBuilder(c.config, &fakeNodeInfo, dokodemoTag)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {

		return err
	}
	outBoundConfig, err = OutboundBuilder(c.config, &fakeNodeInfo, dokodemoTag)
	if err != nil {

		return err
	}
	err = c.addOutbound(outBoundConfig)
	if err != nil {

		return err
	}
	return nil
}

func (c *Controller) addNewUser(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo) (err error) {
	var users []*protocol.User
	switch nodeInfo.NodeType {
	case "V2ray", "Vmess", "Vless":
		if nodeInfo.EnableVless || (nodeInfo.NodeType == "Vless" && nodeInfo.NodeType != "Vmess") {
			users = c.buildVlessUser(userInfo)
		} else {
			users = c.buildVmessUser(userInfo)
		}
	case "Trojan":
		users = c.buildTrojanUser(userInfo)
	case "Shadowsocks":
		users = c.buildSSUser(userInfo, nodeInfo.CypherMethod)
	case "Shadowsocks-Plugin":
		users = c.buildSSPluginUser(userInfo)
	default:
		return fmt.Errorf("unsupported node type: %s", nodeInfo.NodeType)
	}

	err = c.addUsers(users, c.Tag)
	if err != nil {
		return err
	}
	c.logger.Printf("Added %d new users", len(*userInfo))
	return nil
}

func compareUserList(old, new *[]api.UserInfo) (deleted, added []api.UserInfo) {
	mSrc := make(map[api.UserInfo]byte) // 按源数组建索引
	mAll := make(map[api.UserInfo]byte) // 源+目所有元素建索引

	var set []api.UserInfo // 交集

	oldUsers := []api.UserInfo{}
	newUsers := []api.UserInfo{}
	if old != nil {
		oldUsers = *old
	}
	if new != nil {
		newUsers = *new
	}
	// 1.源数组建立map
	for _, v := range oldUsers {
		mSrc[v] = 0
		mAll[v] = 0
	}
	// 2.目数组中，存不进去，即重复元素，所有存不进去的集合就是并集
	for _, v := range newUsers {
		if _, exists := mAll[v]; !exists {
			mAll[v] = 1
		} else {
			set = append(set, v)
		}
	}
	// 3.遍历交集，在并集中找，找到就从并集中删，删完后就是补集（即并-交=所有变化的元素）
	for _, v := range set {
		delete(mAll, v)
	}
	// 4.此时，mall是补集，所有元素去源中找，找到就是删除的，找不到的必定能在目数组中找到，即新加的
	for v := range mAll {
		_, exist := mSrc[v]
		if exist {
			deleted = append(deleted, v)
		} else {
			added = append(added, v)
		}
	}

	return deleted, added
}

func limitUser(c *Controller, user api.UserInfo, silentUsers *[]api.UserInfo) {
	c.limitedUsers[user] = LimitInfo{
		end:               time.Now().Unix() + int64(c.config.AutoSpeedLimitConfig.LimitDuration*60),
		currentSpeedLimit: c.config.AutoSpeedLimitConfig.LimitSpeed,
		originSpeedLimit:  user.SpeedLimit,
	}
	c.logger.Printf("Limit User: %s Speed: %d End: %s", c.buildUserTag(&user), c.config.AutoSpeedLimitConfig.LimitSpeed, time.Unix(c.limitedUsers[user].end, 0).Format("01-02 15:04:05"))
	user.SpeedLimit = uint64((c.config.AutoSpeedLimitConfig.LimitSpeed * 1000000) / 8)
	*silentUsers = append(*silentUsers, user)
}

func (c *Controller) userInfoMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < c.userInterval() {
		return nil
	}

	// Get server status
	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		c.logger.Print(err)
	}
	err = c.apiClient.ReportNodeStatus(
		&api.NodeStatus{
			CPU:    CPU,
			Mem:    Mem,
			Disk:   Disk,
			Uptime: Uptime,
		})
	if err != nil {
		c.logger.Print(err)
	}
	// Unlock users
	if c.config.AutoSpeedLimitConfig.Limit > 0 && len(c.limitedUsers) > 0 {
		c.logger.Printf("Limited users:")
		toReleaseUsers := make([]api.UserInfo, 0)
		for user, limitInfo := range c.limitedUsers {
			if time.Now().Unix() > limitInfo.end {
				user.SpeedLimit = limitInfo.originSpeedLimit
				toReleaseUsers = append(toReleaseUsers, user)
				c.logger.Printf("User: %s Speed: %d End: nil (Unlimit)", c.buildUserTag(&user), user.SpeedLimit)
				delete(c.limitedUsers, user)
			} else {
				c.logger.Printf("User: %s Speed: %d End: %s", c.buildUserTag(&user), limitInfo.currentSpeedLimit, time.Unix(c.limitedUsers[user].end, 0).Format("01-02 15:04:05"))
			}
		}
		if len(toReleaseUsers) > 0 {
			if err := c.UpdateInboundLimiter(c.Tag, &toReleaseUsers); err != nil {
				c.logger.Print(err)
			}
		}
	}

	// Get User traffic. Counters are swapped to 0 at snapshot time so bytes
	// that arrive during the push are not discarded. A failed push adds the
	// snapshot back.
	c.mu.RLock()
	var users []api.UserInfo
	if c.userList != nil {
		users = append([]api.UserInfo(nil), (*c.userList)...)
	}
	tag := c.Tag
	c.mu.RUnlock()

	var userTraffic []api.UserTraffic
	type counterSnap struct {
		n       int64
		counter stats.Counter
	}
	var snaps []counterSnap
	AutoSpeedLimit := int64(0)
	if c.config.AutoSpeedLimitConfig != nil {
		AutoSpeedLimit = int64(c.config.AutoSpeedLimitConfig.Limit)
	}
	UpdatePeriodic := int64(c.userInterval() / time.Second)
	if UpdatePeriodic <= 0 {
		UpdatePeriodic = 60
	}
	limitedUsers := make([]api.UserInfo, 0)
	for _, user := range users {
		email := fmt.Sprintf("%s|%s|%d", tag, user.Email, user.UID)
		upCounter := c.stm.GetCounter("user>>>" + email + ">>>traffic>>>uplink")
		downCounter := c.stm.GetCounter("user>>>" + email + ">>>traffic>>>downlink")
		up := snapshotCounter(upCounter)
		down := snapshotCounter(downCounter)
		if up > 0 || down > 0 {
			// Over speed users
			if AutoSpeedLimit > 0 {
				if down > AutoSpeedLimit*1000000*UpdatePeriodic/8 || up > AutoSpeedLimit*1000000*UpdatePeriodic/8 {
					if _, ok := c.limitedUsers[user]; !ok {
						if c.config.AutoSpeedLimitConfig.WarnTimes == 0 {
							limitUser(c, user, &limitedUsers)
						} else {
							c.warnedUsers[user] += 1
							if c.warnedUsers[user] > c.config.AutoSpeedLimitConfig.WarnTimes {
								limitUser(c, user, &limitedUsers)
								delete(c.warnedUsers, user)
							}
						}
					}
				} else {
					delete(c.warnedUsers, user)
				}
			}
			userTraffic = append(userTraffic, api.UserTraffic{
				UID:      user.UID,
				Email:    user.Email,
				Upload:   up,
				Download: down})
			if up > 0 {
				snaps = append(snaps, counterSnap{n: up, counter: upCounter})
			}
			if down > 0 {
				snaps = append(snaps, counterSnap{n: down, counter: downCounter})
			}
		} else {
			delete(c.warnedUsers, user)
		}
	}
	if len(limitedUsers) > 0 {
		if err := c.UpdateInboundLimiter(tag, &limitedUsers); err != nil {
			c.logger.Print(err)
		}
	}

	if len(userTraffic) > 0 {
		var err error
		if !c.config.DisableUploadTraffic {
			err = c.apiClient.ReportUserTraffic(&userTraffic)
			if err != nil {
				c.logger.Print(err)
				for _, snap := range snaps {
					restoreCounter(snap.counter, snap.n)
				}
			}
		}
	}

	// Report Online info. Only IPs whose user traffic is above the threshold.
	// A uid with no traffic row is not reported.
	if onlineDevice, err := c.GetOnlineDevice(tag); err != nil {
		c.logger.Print(err)
	} else if onlineDevice != nil && len(*onlineDevice) > 0 {
		result := onlineUsersOverThreshold(*onlineDevice, userTraffic, c.config.DeviceOnlineMinTraffic)
		if err = c.apiClient.ReportNodeOnlineUsers(&result); err != nil {
			log.Print(err)
		} else {
			log.Printf("Total %d online users, %d Reported", len(*onlineDevice), len(result))
		}
	}

	// Report Illegal user
	if detectResult, err := c.GetDetectResult(tag); err != nil {
		c.logger.Print(err)
	} else if len(*detectResult) > 0 {
		if err = c.apiClient.ReportIllegal(detectResult); err != nil {
			c.logger.Print(err)
		} else {
			c.logger.Printf("Report %d illegal behaviors", len(*detectResult))
		}

	}
	return nil
}

// func (c *Controller) logPrefix() string {
// 	return fmt.Sprintf("[%s] %s(ID=%d)", c.clientInfo.APIHost, c.nodeInfo.NodeType, c.nodeInfo.NodeID)
// }

// Check Cert
func (c *Controller) certMonitor() error {
	if !c.needsCertMonitor() {
		return nil
	}
	lego, err := mylego.New(c.config.CertConfig)
	if err != nil {
		c.logger.Print(err)
		return nil
	}
	// Xray-core supports the OcspStapling certification hot renew
	_, _, _, err = lego.RenewCert()
	if err != nil {
		c.logger.Print(err)
	}
	return nil
}
