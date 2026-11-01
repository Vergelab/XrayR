package mydispatcher

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// v26 enables splice only when CanSpliceCopy == 2, then promotes it to 1.
// The vless inbound sets 2 for Vision before DispatchLink. Forcing 3 here
// keeps the rate limiter and traffic counters on the path.
func TestPrepareOutboundLinkDisablesSplice(t *testing.T) {
	upReader, upWriter := pipe.New()
	downReader, downWriter := pipe.New()
	defer common.Close(upReader)
	defer common.Close(upWriter)
	defer common.Close(downReader)
	defer common.Close(downWriter)
	inbound := &session.Inbound{CanSpliceCopy: 2}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	link := &transport.Link{Reader: upReader, Writer: downWriter}
	if _, err := (&DefaultDispatcher{}).prepareOutboundLink(ctx, link); err != nil {
		t.Fatal(err)
	}
	if inbound.CanSpliceCopy != 3 {
		t.Fatalf("CanSpliceCopy = %d, want 3", inbound.CanSpliceCopy)
	}
}
