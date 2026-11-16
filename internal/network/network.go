// Package network selects a host multicast interface and platform group.
package network

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Platform includes OS options, architecture and CPU variant. FormatAll also
// canonicalizes the OS feature ordering so equivalent identities hash alike.
func Platform(p ocispec.Platform) string { return platforms.FormatAll(platforms.Normalize(p)) }

// Group hashes the complete normalized platform into the local-scope block
// 239.192.0.0/14. Receivers must still compare full platform identities.
func Group(platform string) net.IP {
	h := sha256.Sum256([]byte(platform))
	return net.IPv4(239, 192|(h[0]&3), h[1], h[2])
}

type route struct {
	name   string
	metric uint64
}

func defaultRoutes(r io.Reader) []route {
	var routes []route
	s := bufio.NewScanner(r)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&1 == 0 || flags&0x200 != 0 {
			continue
		}
		metric, err := strconv.ParseUint(f[6], 10, 64)
		if err == nil {
			routes = append(routes, route{f[0], metric})
		}
	}
	return routes
}

func ipv4(iface *net.Interface, advertised string) (net.IP, error) {
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 || iface.Flags&net.FlagLoopback != 0 {
		return nil, fmt.Errorf("interface %s must be up, multicast-capable and non-loopback", iface.Name)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil || ip.To4() == nil || !ip.IsGlobalUnicast() {
			continue
		}
		if advertised == "" || ip.Equal(net.ParseIP(advertised)) {
			return ip.To4(), nil
		}
	}
	return nil, fmt.Errorf("interface %s has no matching unicast IPv4 address", iface.Name)
}

func Discover(name, advertised string) (*net.Interface, net.IP, error) {
	if name != "" {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, nil, err
		}
		ip, err := ipv4(iface, advertised)
		return iface, ip, err
	}
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, nil, fmt.Errorf("read host routes: %w", err)
	}
	var best *net.Interface
	var bestIP net.IP
	metric := ^uint64(0)
	for _, route := range defaultRoutes(strings.NewReader(string(data))) {
		if route.metric >= metric {
			continue
		}
		iface, err := net.InterfaceByName(route.name)
		if err != nil {
			continue
		}
		ip, err := ipv4(iface, advertised)
		if err != nil {
			continue
		}
		best, bestIP, metric = iface, ip, route.metric
	}
	if best == nil {
		return nil, nil, fmt.Errorf("no usable IPv4 default-route interface; set MULTICAST_INTERFACE")
	}
	return best, bestIP, nil
}
