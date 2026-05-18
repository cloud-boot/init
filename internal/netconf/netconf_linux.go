//go:build linux

// Package netconf brings up the first virtio-net interface and obtains an
// address via DHCPv4. The cmdline `ip=` parameter is also supported (static).
package netconf

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/vishvananda/netlink"
)

// Config describes the resolved L3 settings for an interface.
type Config struct {
	Iface   string
	Addr    net.IPNet
	Gateway net.IP
	DNS     []net.IP
}

// Setup configures lo and the first non-loopback link with carrier.
// If cmdlineIP is non-empty in the form "addr::gw:mask::iface:..." (klibc syntax),
// it is used; otherwise DHCPv4 is attempted.
func Setup(cmdlineIP string) (*Config, error) {
	if err := bringUpLoopback(); err != nil {
		return nil, err
	}

	link, err := pickInterface()
	if err != nil {
		return nil, err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("link up %s: %w", link.Attrs().Name, err)
	}

	if cmdlineIP != "" {
		return applyStatic(link, cmdlineIP)
	}
	return doDHCP(link)
}

func bringUpLoopback() error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("lookup lo: %w", err)
	}
	return netlink.LinkSetUp(lo)
}

func pickInterface() (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, l := range links {
			a := l.Attrs()
			if a.Name == "lo" {
				continue
			}
			if a.EncapType == "ether" || strings.HasPrefix(a.Name, "en") || strings.HasPrefix(a.Name, "eth") {
				return l, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no usable interface found")
		}
		time.Sleep(500 * time.Millisecond)
		links, _ = netlink.LinkList()
	}
}

func applyStatic(link netlink.Link, spec string) (*Config, error) {
	// klibc ip= form: client::gw:mask::iface[:proto]
	parts := strings.Split(spec, ":")
	if len(parts) < 5 {
		return nil, fmt.Errorf("invalid ip= spec: %q", spec)
	}
	client := net.ParseIP(parts[0])
	gw := net.ParseIP(parts[2])
	mask := net.ParseIP(parts[3])
	if client == nil || mask == nil {
		return nil, fmt.Errorf("invalid ip= spec: %q", spec)
	}
	cidr := net.IPNet{IP: client, Mask: net.IPMask(mask.To4())}
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: &cidr}); err != nil {
		return nil, fmt.Errorf("addr add: %w", err)
	}
	if gw != nil {
		_ = netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Gw: gw})
	}
	return &Config{Iface: link.Attrs().Name, Addr: cidr, Gateway: gw}, nil
}

func doDHCP(link netlink.Link) (*Config, error) {
	name := link.Attrs().Name
	log.Printf("netconf: dhcp on %s", name)

	c, err := nclient4.New(name)
	if err != nil {
		return nil, fmt.Errorf("dhcp client: %w", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lease, err := c.Request(ctx)
	if err != nil {
		return nil, fmt.Errorf("dhcp request: %w", err)
	}
	ack := lease.ACK
	addr := &net.IPNet{IP: ack.YourIPAddr, Mask: ack.SubnetMask()}
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: addr}); err != nil {
		return nil, fmt.Errorf("addr add: %w", err)
	}
	var gw net.IP
	if rs := ack.Router(); len(rs) > 0 {
		gw = rs[0]
		_ = netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Gw: gw})
	}
	cfg := &Config{Iface: name, Addr: *addr, Gateway: gw, DNS: ack.DNS()}
	writeResolvConf(cfg.DNS)
	return cfg, nil
}

func writeResolvConf(dns []net.IP) {
	if len(dns) == 0 {
		return
	}
	var b strings.Builder
	for _, ip := range dns {
		fmt.Fprintf(&b, "nameserver %s\n", ip.String())
	}
	_ = writeFile("/etc/resolv.conf", []byte(b.String()), 0o644)
}

// WriteResolvConf is the public hook for overriding /etc/resolv.conf
// after netconf.Setup has already run with DHCP-supplied DNS. cloud-
// boot-init uses it to honour `cloudboot.dns=` from the kernel cmdline
// (early) and the plan's `dns = [...]` field (after plan parse). Empty
// `ips` is a no-op so the DHCP default keeps its place.
func WriteResolvConf(ips []net.IP) { writeResolvConf(ips) }
