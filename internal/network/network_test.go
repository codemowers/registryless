package network

import (
	"strings"
	"testing"
)

func TestPlatformGroups(t *testing.T) {
	seen := map[string]string{}
	for _, platform := range []string{"linux/amd64", "linux/arm64", "linux/arm/v6", "linux/arm/v7", "windows/amd64", "freebsd/amd64"} {
		ip := Group(platform)
		if ip[12] != 239 || ip[13] < 192 || ip[13] > 195 {
			t.Fatalf("group outside administrative scope: %s", ip)
		}
		if previous, ok := seen[ip.String()]; ok {
			t.Fatalf("test platform collision: %s, %s", previous, platform)
		}
		seen[ip.String()] = platform
		if !ip.Equal(Group(platform)) {
			t.Fatal("group is not deterministic")
		}
	}
}

func TestDefaultRoutes(t *testing.T) {
	routes := defaultRoutes(strings.NewReader(`Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
eth0 00000000 0100000A 0003 0 0 100 00000000 0 0 0
eth1 00000000 0100010A 0003 0 0 20 00000000 0 0 0
down 00000000 00000000 0000 0 0 1 00000000 0 0 0
reject 00000000 00000000 0201 0 0 1 00000000 0 0 0
veth0 0000010A 00000000 0001 0 0 0 00FFFFFF 0 0 0
`))
	if len(routes) != 2 || routes[0].name != "eth0" || routes[1].metric != 20 {
		t.Fatalf("unexpected usable defaults: %#v", routes)
	}
}
