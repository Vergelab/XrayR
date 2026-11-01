package limiter

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Vergelab/XrayR/api"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

func TestDeviceLimitDistinctLocalIPs(t *testing.T) {
	l := New()
	users := []api.UserInfo{{
		UID:         7,
		Email:       "u@x",
		SpeedLimit:  0,
		DeviceLimit: 1,
	}}
	if err := l.AddInboundLimiter("tag", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	email := "tag|u@x|7"
	_, _, reject := l.GetUserBucket("tag", email, "10.0.0.1", true)
	if reject {
		t.Fatal("first ip rejected")
	}
	_, _, reject = l.GetUserBucket("tag", email, "10.0.0.2", true)
	if !reject {
		t.Fatal("second ip was allowed")
	}
	_, _, reject = l.GetUserBucket("tag", email, "10.0.0.1", true)
	if reject {
		t.Fatal("same ip rejected")
	}
}

func TestDeviceLimitHonorsPanelAlive(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 7, Email: "u@x", DeviceLimit: 2}}
	if err := l.AddInboundLimiter("tag", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	value, _ := l.InboundInfo.Load("tag")
	value.(*InboundInfo).SetAliveList(map[int]int{7: 2})
	_, _, reject := l.GetUserBucket("tag", "tag|u@x|7", "10.0.0.1", true)
	if !reject {
		t.Fatal("panel alive at the limit should reject a new local ip")
	}
}

func TestOldUserOnlineUIDBypass(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 2, Email: "b@x", DeviceLimit: 1}}
	if err := l.AddInboundLimiter("tag", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	value, _ := l.InboundInfo.Load("tag")
	in := value.(*InboundInfo)
	in.OldUserOnline.Store("10.0.0.9", 1)
	in.SetAliveList(map[int]int{2: 1})
	_, _, reject := l.GetUserBucket("tag", "tag|b@x|2", "10.0.0.9", true)
	if !reject {
		t.Fatal("different uid reused an old ip and skipped the limit")
	}
}

func TestSameUserReconnectIsNotANewDevice(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 2, Email: "b@x", DeviceLimit: 1}}
	if err := l.AddInboundLimiter("tag", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	value, _ := l.InboundInfo.Load("tag")
	in := value.(*InboundInfo)
	in.OldUserOnline.Store("10.0.0.9", 2)
	_, _, reject := l.GetUserBucket("tag", "tag|b@x|2", "10.0.0.9", true)
	if reject {
		t.Fatal("same user reconnect rejected")
	}
}

func TestOldUserOnlineSweep(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 2, Email: "b@x", DeviceLimit: 2}}
	if err := l.AddInboundLimiter("tag", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	value, _ := l.InboundInfo.Load("tag")
	in := value.(*InboundInfo)
	in.OldUserOnline.Store("stale", 2)
	ipMap := new(sync.Map)
	ipMap.Store("10.0.0.1", 2)
	in.UserOnlineIP.Store("tag|b@x|2", ipMap)
	online, err := l.GetOnlineDevice("tag")
	if err != nil {
		t.Fatal(err)
	}
	if len(*online) != 1 || (*online)[0].IP != "10.0.0.1" {
		t.Fatalf("online = %#v", *online)
	}
	if _, ok := in.OldUserOnline.Load("stale"); ok {
		t.Fatal("stale OldUserOnline entry survived the sweep")
	}
	if _, ok := in.OldUserOnline.Load("10.0.0.1"); !ok {
		t.Fatal("current ip was not kept")
	}
}

func TestSeparateUpDownBuckets(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "a@b", SpeedLimit: 1000}}
	if err := l.AddInboundLimiter("t", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	up, down, reject := l.GetUserBucket("t", "t|a@b|1", "1.1.1.1", true)
	if reject || up == nil || down == nil {
		t.Fatalf("up=%v down=%v reject=%v", up, down, reject)
	}
	if up == down {
		t.Fatal("upload and download share one bucket")
	}
	if !up.AllowN(time.Now(), up.Burst()) {
		t.Fatal("could not drain upload bucket")
	}
	if !down.Allow() {
		t.Fatal("download bucket was drained with the upload bucket")
	}
}

func TestWaitNSplitsAndErrorSkipsWrite(t *testing.T) {
	lim := rate.NewLimiter(rate.Inf, 10)
	if err := waitN(context.Background(), lim, 25); err != nil {
		t.Fatal(err)
	}
	writer := &captureWriter{}
	limited := &Writer{writer: writer, limiter: rate.NewLimiter(rate.Inf, 0)}
	mb := buf.MultiBuffer{buf.New()}
	mb[0].Write([]byte("hello"))
	if err := limited.WriteMultiBuffer(mb); err == nil {
		t.Fatal("expected wait error")
	}
	if writer.wrote {
		t.Fatal("buffer was written after WaitN failed")
	}
}

type captureWriter struct {
	wrote bool
}

func (c *captureWriter) WriteMultiBuffer(buf.MultiBuffer) error {
	c.wrote = true
	return nil
}
