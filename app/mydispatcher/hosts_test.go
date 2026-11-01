package mydispatcher

import (
	"context"
	"testing"

	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/features/dns"
)

func TestLookupStaticHost(t *testing.T) {
	server, err := appdns.New(context.Background(), &appdns.Config{
		QueryStrategy: appdns.QueryStrategy_USE_IP,
		StaticHosts: []*appdns.Config_HostMapping{
			{
				Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{
					Type:  geodata.Domain_Full,
					Value: "static.example",
				}}},
				Ip: [][]byte{{9, 9, 9, 9}},
			},
			{
				Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{
					Type:  geodata.Domain_Full,
					Value: "alias.example",
				}}},
				ProxiedDomain: "other.example",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := dns.Client(server)

	ip, ok := lookupStaticHost(client, "static.example")
	if !ok || !ip.Family().IsIP() || ip.String() != "9.9.9.9" {
		t.Fatalf("static ip lookup = %v ok=%v", ip, ok)
	}
	alias, ok := lookupStaticHost(client, "alias.example.")
	if !ok || !alias.Family().IsDomain() || alias.Domain() != "other.example" {
		t.Fatalf("alias lookup = %v ok=%v", alias, ok)
	}
	if _, ok := lookupStaticHost(client, "missing.example"); ok {
		t.Fatal("missing domain was replaced")
	}
	// Destination.String() is "tcp:host:port" and must not be used as the lookup key.
	if _, ok := lookupStaticHost(client, "tcp:static.example:443"); ok {
		t.Fatal("destination string matched a host rule")
	}
}
