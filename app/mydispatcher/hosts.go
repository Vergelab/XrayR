package mydispatcher

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
)

// lookupStaticHost replaces dns.HostsLookup, which xray-core removed.
//
// Static host mappings used to be applied in the dispatcher before routing and
// before dialing. That still matters here: XrayR's default freedom strategy is
// AsIs, so the outbound never asks the xray DNS client, and dns.Client.LookupIP
// would also follow a domain alias through a real resolver instead of handing
// the alias back. The DNS app keeps the table in an unexported StaticHosts
// value whose Lookup method is still exported, so this reads that table.
func lookupStaticHost(client dns.Client, domain string) (addr net.Address, ok bool) {
	defer func() {
		if recover() != nil {
			logHostsLookupOnce()
			addr, ok = nil, false
		}
	}()

	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if client == nil || domain == "" {
		return nil, false
	}

	rv := reflect.ValueOf(client)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return nil, false
	}
	elem := rv.Elem()
	if elem.Kind() != reflect.Struct {
		return nil, false
	}
	hostsField := elem.FieldByName("hosts")
	if !hostsField.IsValid() || hostsField.Kind() != reflect.Pointer || hostsField.IsNil() {
		return nil, false
	}

	option := dns.IPOption{IPv4Enable: true, IPv6Enable: true}
	if ipField := elem.FieldByName("ipOption"); ipField.IsValid() && ipField.Kind() == reflect.Pointer && !ipField.IsNil() {
		ipOpt := reflect.NewAt(ipField.Type(), unsafe.Pointer(ipField.UnsafeAddr())).Elem().Interface().(*dns.IPOption)
		if ipOpt != nil {
			option = *ipOpt
			option.FakeEnable = false
		}
	}

	hosts := reflect.NewAt(hostsField.Type(), unsafe.Pointer(hostsField.UnsafeAddr())).Elem()
	method := hosts.MethodByName("Lookup")
	if !method.IsValid() {
		logHostsLookupOnce()
		return nil, false
	}
	out := method.Call([]reflect.Value{
		reflect.ValueOf(domain),
		reflect.ValueOf(option),
	})
	if len(out) != 2 || (out[1].IsValid() && !out[1].IsNil()) {
		return nil, false
	}
	addrs, cast := out[0].Interface().([]net.Address)
	if !cast || len(addrs) == 0 || addrs[0] == nil {
		return nil, false
	}
	switch addrs[0].(type) {
	case dns.RCodeError:
		return nil, false
	}
	family := addrs[0].Family()
	if !family.IsDomain() && !family.IsIP() {
		return nil, false
	}
	if family.IsDomain() && addrs[0].Domain() == "" {
		return nil, false
	}
	return addrs[0], true
}

var logHostsLookupOnce = sync.OnceFunc(func() {
	errors.LogWarning(context.Background(), "XrayR static-host lookup could not read the xray DNS hosts table; dns.json hosts will not rewrite destinations")
})
