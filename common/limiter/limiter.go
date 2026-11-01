// Package limiter is to control the links that go into the dispatcher
package limiter

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Vergelab/XrayR/api"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/marshaler"
	"github.com/eko/gocache/lib/v4/store"
	goCacheStore "github.com/eko/gocache/store/go_cache/v4"
	redisStore "github.com/eko/gocache/store/redis/v4"
	goCache "github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

type UserInfo struct {
	UID         int
	SpeedLimit  uint64
	DeviceLimit int
}

type InboundInfo struct {
	Tag            string
	NodeSpeedLimit uint64
	UserInfo       *sync.Map // Key: Email value: UserInfo
	BucketHub      *sync.Map // key: Email, value: *rate.Limiter
	UserOnlineIP   *sync.Map // Key: Email, value: {Key: IP, value: UID}
	GlobalLimit    struct {
		config         *GlobalDeviceLimitConfig
		globalOnlineIP *marshaler.Marshaler
	}
	alive         atomic.Value // map[int]int, key uid, value panel alive IP count
	OldUserOnline *sync.Map    // Key: Ip, value: Uid
}

// directionLimiters is one token bucket per direction. A panel speed_limit
// applies to upload and download separately; sharing one bucket would cut
// the allowance in half when both directions are busy.
type directionLimiters struct {
	Up   *rate.Limiter
	Down *rate.Limiter
}

type Limiter struct {
	InboundInfo *sync.Map // Key: Tag, Value: *InboundInfo
}

func New() *Limiter {
	return &Limiter{
		InboundInfo: new(sync.Map),
	}
}

func (l *Limiter) AddInboundLimiter(tag string, nodeSpeedLimit uint64, userList *[]api.UserInfo, globalLimit *GlobalDeviceLimitConfig) error {
	inboundInfo := &InboundInfo{
		Tag:            tag,
		NodeSpeedLimit: nodeSpeedLimit,
		BucketHub:      new(sync.Map),
		UserOnlineIP:   new(sync.Map),
		OldUserOnline:  new(sync.Map),
	}
	inboundInfo.storeAlive(nil)

	if globalLimit != nil && globalLimit.Enable {
		inboundInfo.GlobalLimit.config = globalLimit

		// init local store
		gs := goCacheStore.NewGoCache(goCache.New(time.Duration(globalLimit.Expiry)*time.Second, 1*time.Minute))

		// init redis store
		rs := redisStore.NewRedis(redis.NewClient(
			&redis.Options{
				Network:  globalLimit.RedisNetwork,
				Addr:     globalLimit.RedisAddr,
				Username: globalLimit.RedisUsername,
				Password: globalLimit.RedisPassword,
				DB:       globalLimit.RedisDB,
			}),
			store.WithExpiration(time.Duration(globalLimit.Expiry)*time.Second))

		// init chained cache. First use local go-cache, if go-cache is nil, then use redis cache
		cacheManager := cache.NewChain[any](
			cache.New[any](gs), // go-cache is priority
			cache.New[any](rs),
		)
		inboundInfo.GlobalLimit.globalOnlineIP = marshaler.New(cacheManager)
	}

	userMap := new(sync.Map)
	for _, u := range *userList {
		userMap.Store(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID), UserInfo{
			UID:         u.UID,
			SpeedLimit:  u.SpeedLimit,
			DeviceLimit: u.DeviceLimit,
		})
	}
	inboundInfo.UserInfo = userMap
	l.InboundInfo.Store(tag, inboundInfo) // Replace the old inbound info
	return nil
}

func (l *Limiter) UpdateInboundLimiter(tag string, updatedUserList *[]api.UserInfo) error {
	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		// Update User info
		for _, u := range *updatedUserList {
			inboundInfo.UserInfo.Store(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID), UserInfo{
				UID:         u.UID,
				SpeedLimit:  u.SpeedLimit,
				DeviceLimit: u.DeviceLimit,
			})
			// Update old limiter bucket
			limit := determineRate(inboundInfo.NodeSpeedLimit, u.SpeedLimit)
			bucketKey := fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID)
			if limit > 0 {
				if bucket, ok := inboundInfo.BucketHub.Load(bucketKey); ok {
					pair := bucket.(*directionLimiters)
					pair.Up.SetLimit(rate.Limit(limit))
					pair.Up.SetBurst(int(limit))
					pair.Down.SetLimit(rate.Limit(limit))
					pair.Down.SetBurst(int(limit))
				}
			} else {
				inboundInfo.BucketHub.Delete(bucketKey)
			}
		}
	} else {
		return fmt.Errorf("no such inbound in limiter: %s", tag)
	}
	return nil
}

func (l *Limiter) DeleteInboundLimiter(tag string) error {
	l.InboundInfo.Delete(tag)
	return nil
}

func (l *Limiter) GetOnlineDevice(tag string) (*[]api.OnlineUser, error) {
	var onlineUser []api.OnlineUser

	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		// Clear Speed Limiter bucket for users who are not online
		inboundInfo.BucketHub.Range(func(key, value interface{}) bool {
			email := key.(string)
			if _, exists := inboundInfo.UserOnlineIP.Load(email); !exists {
				inboundInfo.BucketHub.Delete(email)
			}
			return true
		})
		seen := make(map[string]struct{})
		inboundInfo.UserOnlineIP.Range(func(key, value interface{}) bool {
			email := key.(string)
			ipMap := value.(*sync.Map)
			ipMap.Range(func(key, value interface{}) bool {
				uid := value.(int)
				ip := key.(string)
				inboundInfo.OldUserOnline.Store(ip, uid)
				seen[ip] = struct{}{}
				onlineUser = append(onlineUser, api.OnlineUser{UID: uid, IP: ip})
				return true
			})
			inboundInfo.UserOnlineIP.Delete(email) // Reset online device
			return true
		})
		// Drop IPs that were not refreshed this cycle. A stale entry would
		// let the next connection skip the device check.
		inboundInfo.OldUserOnline.Range(func(key, _ interface{}) bool {
			ip := key.(string)
			if _, ok := seen[ip]; !ok {
				inboundInfo.OldUserOnline.Delete(ip)
			}
			return true
		})
	} else {
		return nil, fmt.Errorf("no such inbound in limiter: %s", tag)
	}

	return &onlineUser, nil
}

func (l *Limiter) GetUserBucket(tag string, email string, ip string, isSourceTCP bool) (up *rate.Limiter, down *rate.Limiter, Reject bool) {
	if value, ok := l.InboundInfo.Load(tag); ok {
		var (
			userLimit        uint64 = 0
			deviceLimit, uid int
		)

		inboundInfo := value.(*InboundInfo)
		nodeLimit := inboundInfo.NodeSpeedLimit

		if v, ok := inboundInfo.UserInfo.Load(email); ok {
			u := v.(UserInfo)
			uid = u.UID
			userLimit = u.SpeedLimit
			deviceLimit = u.DeviceLimit
		}

		// Local device limit counts distinct source IPs on this node, and also
		// rejects when the panel alive count is already at the limit.
		if isSourceTCP && rejectDevice(inboundInfo, email, ip, uid, deviceLimit) {
			return nil, nil, true
		}

		// GlobalLimit
		if inboundInfo.GlobalLimit.config != nil && inboundInfo.GlobalLimit.config.Enable {
			if reject := globalLimit(inboundInfo, email, uid, ip, deviceLimit); reject {
				return nil, nil, true
			}
		}

		// Speed limit. Each direction gets the full allowance.
		limit := determineRate(nodeLimit, userLimit)
		if limit > 0 {
			pair := &directionLimiters{
				Up:   rate.NewLimiter(rate.Limit(limit), int(limit)),
				Down: rate.NewLimiter(rate.Limit(limit), int(limit)),
			}
			if v, ok := inboundInfo.BucketHub.LoadOrStore(email, pair); ok {
				existing := v.(*directionLimiters)
				return existing.Up, existing.Down, false
			}
			return pair.Up, pair.Down, false
		}
		return nil, nil, false
	}
	log.Error("Get Inbound Limiter information failed")
	return nil, nil, false
}

func (in *InboundInfo) storeAlive(m map[int]int) {
	if m == nil {
		m = map[int]int{}
	}
	cp := make(map[int]int, len(m))
	for k, v := range m {
		cp[k] = v
	}
	in.alive.Store(cp)
}

// SetAliveList replaces the panel alive snapshot. The map is copied so the
// caller can reuse its buffer. A failed poll must not call this.
func (in *InboundInfo) SetAliveList(m map[int]int) {
	in.storeAlive(m)
}

func (in *InboundInfo) aliveCount(uid int) int {
	m, _ := in.alive.Load().(map[int]int)
	if m == nil {
		return 0
	}
	return m[uid]
}

// rejectDevice reports whether this TCP source IP would exceed the user's
// device limit. Local IPs already on this node count, and so does the panel
// alive total when the panel has one. A same-user reconnect of an IP seen
// last cycle is the same device. A different uid does not inherit that pass.
func rejectDevice(inboundInfo *InboundInfo, email, ip string, uid, deviceLimit int) bool {
	fresh := new(sync.Map)
	fresh.Store(ip, uid)
	alive := inboundInfo.aliveCount(uid)
	v, loaded := inboundInfo.UserOnlineIP.LoadOrStore(email, fresh)
	if !loaded {
		if old, ok := inboundInfo.OldUserOnline.Load(ip); ok && old.(int) == uid {
			inboundInfo.OldUserOnline.Delete(ip)
			return false
		}
		if deviceLimit > 0 && (1 > deviceLimit || alive >= deviceLimit) {
			inboundInfo.UserOnlineIP.Delete(email)
			return true
		}
		return false
	}
	ipMap := v.(*sync.Map)
	if _, exists := ipMap.Load(ip); exists {
		return false
	}
	if deviceLimit > 0 {
		count := 0
		ipMap.Range(func(_, _ interface{}) bool {
			count++
			return true
		})
		if count+1 > deviceLimit || alive >= deviceLimit {
			return true
		}
	}
	ipMap.Store(ip, uid)
	return false
}

// Global device limit
func globalLimit(inboundInfo *InboundInfo, email string, uid int, ip string, deviceLimit int) bool {

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(inboundInfo.GlobalLimit.config.Timeout)*time.Second)
	defer cancel()

	// reformat email for unique key
	uniqueKey := strings.Replace(email, inboundInfo.Tag, strconv.Itoa(deviceLimit), 1)

	v, err := inboundInfo.GlobalLimit.globalOnlineIP.Get(ctx, uniqueKey, new(map[string]int))
	if err != nil {
		if _, ok := err.(*store.NotFound); ok {
			// If the email is a new device
			go pushIP(inboundInfo, uniqueKey, &map[string]int{ip: uid})
		} else {
			log.Error("cache service", err)
		}
		return false
	}

	ipMap := v.(*map[string]int)
	// Reject device reach limit directly
	if deviceLimit > 0 && len(*ipMap) > deviceLimit {
		return true
	}

	// If the ip is not in cache
	if _, ok := (*ipMap)[ip]; !ok {
		(*ipMap)[ip] = uid
		go pushIP(inboundInfo, uniqueKey, ipMap)
	}

	return false
}

// push the ip to cache
func pushIP(inboundInfo *InboundInfo, uniqueKey string, ipMap *map[string]int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(inboundInfo.GlobalLimit.config.Timeout)*time.Second)
	defer cancel()

	if err := inboundInfo.GlobalLimit.globalOnlineIP.Set(ctx, uniqueKey, ipMap); err != nil {
		log.Error("cache service", err)
	}
}

// determineRate returns the minimum non-zero rate
func determineRate(nodeLimit, userLimit uint64) (limit uint64) {
	if nodeLimit == 0 || userLimit == 0 {
		if nodeLimit > userLimit {
			return nodeLimit
		} else if nodeLimit < userLimit {
			return userLimit
		} else {
			return 0
		}
	} else {
		if nodeLimit > userLimit {
			return userLimit
		} else if nodeLimit < userLimit {
			return nodeLimit
		} else {
			return nodeLimit
		}
	}
}
