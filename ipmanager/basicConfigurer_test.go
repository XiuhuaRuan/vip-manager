package ipmanager

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func testIPConfiguration(vip string) *IPConfiguration {
	return &IPConfiguration{
		VIP:     netip.MustParseAddr(vip),
		Netmask: net.CIDRMask(24, 32),
		Iface: net.Interface{
			Name:         "test0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}
}

// ---------------------------------------------------------------------------
// newBasicConfigurer
// ---------------------------------------------------------------------------

func TestNewBasicConfigurer_LoopbackMAC(t *testing.T) {
	t.Parallel()

	cfg := &IPConfiguration{
		VIP:     netip.MustParseAddr("192.168.1.10"),
		Netmask: net.CIDRMask(24, 32),
		Iface: net.Interface{
			Name:         "lo",
			HardwareAddr: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	_, err := newBasicConfigurer(cfg)
	if err == nil {
		t.Fatal("expected error for loopback hardware address, got nil")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("loopback")) {
		t.Errorf("expected error to mention loopback, got: %v", err)
	}
}

func TestNewBasicConfigurer_NilHardwareAddr(t *testing.T) {
	t.Parallel()

	cfg := &IPConfiguration{
		VIP:     netip.MustParseAddr("192.168.1.10"),
		Netmask: net.CIDRMask(24, 32),
		Iface: net.Interface{
			Name:         "eth0",
			HardwareAddr: nil,
		},
	}

	_, err := newBasicConfigurer(cfg)
	if err == nil {
		t.Fatal("expected error for nil hardware address, got nil")
	}
}

func TestNewBasicConfigurer_Success(t *testing.T) {
	t.Parallel()

	cfg := testIPConfiguration("192.168.1.10")
	c, err := newBasicConfigurer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected configurer, got nil")
	}
	if c.IPConfiguration != cfg {
		t.Error("configurer did not retain the provided IPConfiguration")
	}
}

// ---------------------------------------------------------------------------
// queryAddress
// ---------------------------------------------------------------------------

func TestBasicConfigurer_queryAddress_MissingInterface(t *testing.T) {
	t.Parallel()

	c := &BasicConfigurer{
		IPConfiguration: testIPConfiguration("192.168.1.10"),
	}

	// The interface name is fake, so the lookup fails and queryAddress must
	// report that the address is not assigned.
	if got := c.queryAddress(); got {
		t.Errorf("queryAddress() = %v, want false for non-existent interface", got)
	}
}

func TestBasicConfigurer_queryAddress_RealInterface_NotAssigned(t *testing.T) {
	t.Parallel()

	// Get the loopback interface which should exist on all systems
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("loopback interface not available")
	}

	// Use an address that is very unlikely to be assigned to loopback
	c := &BasicConfigurer{
		IPConfiguration: &IPConfiguration{
			VIP:     netip.MustParseAddr("203.0.113.99"), // TEST-NET-3 (RFC 5737)
			Netmask: net.CIDRMask(32, 32),
			Iface: net.Interface{
				Name:         lo.Name,
				HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			},
		},
	}

	// Should return false since this address is not assigned
	if got := c.queryAddress(); got {
		t.Errorf("queryAddress() = %v, want false for unassigned address", got)
	}
}

func TestBasicConfigurer_queryAddress_RealInterface_Assigned(t *testing.T) {
	t.Parallel()

	// Get the loopback interface
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("loopback interface not available")
	}

	// Get addresses assigned to loopback
	addrs, err := lo.Addrs()
	if err != nil || len(addrs) == 0 {
		t.Skip("cannot get addresses for loopback interface")
	}

	// Find an IPv4 address
	var testAddr netip.Addr
	var testMask net.IPMask
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.IP.To4() != nil {
				testAddr, err = netip.ParseAddr(ipNet.IP.String())
				if err != nil {
					continue
				}
				testMask = ipNet.Mask
				break
			}
		}
	}

	if !testAddr.IsValid() {
		t.Skip("no IPv4 address found on loopback")
	}

	c := &BasicConfigurer{
		IPConfiguration: &IPConfiguration{
			VIP:     testAddr,
			Netmask: testMask,
			Iface: net.Interface{
				Name:         lo.Name,
				HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			},
		},
	}

	// Should return true since this address is actually assigned to loopback
	if got := c.queryAddress(); !got {
		t.Errorf("queryAddress() = %v, want true for assigned address %s", got, testAddr)
	}
}

// ---------------------------------------------------------------------------
// createGratuitousARP
// ---------------------------------------------------------------------------

func TestBasicConfigurer_createGratuitousARP(t *testing.T) {
	t.Parallel()

	c := &BasicConfigurer{
		IPConfiguration: testIPConfiguration("192.168.1.10"),
	}

	packet, err := c.createGratuitousARP()
	if err != nil {
		t.Fatalf("createGratuitousARP() error = %v", err)
	}

	parsed := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default)

	ethLayer := parsed.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		t.Fatal("missing Ethernet layer")
	}
	eth := ethLayer.(*layers.Ethernet)

	if !bytes.Equal(eth.SrcMAC, c.Iface.HardwareAddr) {
		t.Errorf("Ethernet source MAC = %v, want %v", eth.SrcMAC, c.Iface.HardwareAddr)
	}
	wantBroadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if !bytes.Equal(eth.DstMAC, wantBroadcast) {
		t.Errorf("Ethernet destination MAC = %v, want broadcast", eth.DstMAC)
	}
	if eth.EthernetType != layers.EthernetTypeARP {
		t.Errorf("Ethernet type = %v, want ARP", eth.EthernetType)
	}

	arpLayer := parsed.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		t.Fatal("missing ARP layer")
	}
	arp := arpLayer.(*layers.ARP)

	if arp.AddrType != layers.LinkTypeEthernet {
		t.Errorf("ARP hardware type = %v, want Ethernet", arp.AddrType)
	}
	if arp.Protocol != layers.EthernetTypeIPv4 {
		t.Errorf("ARP protocol type = %v, want IPv4", arp.Protocol)
	}
	if arp.HwAddressSize != MACAddressSize {
		t.Errorf("ARP hardware address size = %d, want %d", arp.HwAddressSize, MACAddressSize)
	}
	if arp.ProtAddressSize != IPv4AddressSize {
		t.Errorf("ARP protocol address size = %d, want %d", arp.ProtAddressSize, IPv4AddressSize)
	}
	if arp.Operation != layers.ARPReply {
		t.Errorf("ARP operation = %d, want reply", arp.Operation)
	}
	if !bytes.Equal(arp.SourceHwAddress, c.Iface.HardwareAddr) {
		t.Errorf("ARP source hardware address = %v, want %v", arp.SourceHwAddress, c.Iface.HardwareAddr)
	}
	if !bytes.Equal(arp.SourceProtAddress, c.VIP.AsSlice()) {
		t.Errorf("ARP source protocol address = %v, want %v", arp.SourceProtAddress, c.VIP.AsSlice())
	}
	if !bytes.Equal(arp.DstHwAddress, c.Iface.HardwareAddr) {
		t.Errorf("ARP destination hardware address = %v, want %v", arp.DstHwAddress, c.Iface.HardwareAddr)
	}
	if !bytes.Equal(arp.DstProtAddress, c.VIP.AsSlice()) {
		t.Errorf("ARP destination protocol address = %v, want %v", arp.DstProtAddress, c.VIP.AsSlice())
	}
}

func TestBasicConfigurer_createGratuitousNA(t *testing.T) {
	t.Parallel()

	c := &BasicConfigurer{
		IPConfiguration: &IPConfiguration{
			VIP: netip.MustParseAddr("2001:db8::10"),
			Iface: net.Interface{
				HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			},
		},
	}
	sourceIP := net.ParseIP("fe80::1")

	packet, err := c.createGratuitousNA(sourceIP)
	if err != nil {
		t.Fatalf("createGratuitousNA() error = %v", err)
	}

	parsed := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default)
	eth := parsed.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	wantMulticast := net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}
	if !bytes.Equal(eth.DstMAC, wantMulticast) {
		t.Errorf("Ethernet destination MAC = %v, want %v", eth.DstMAC, wantMulticast)
	}
	if eth.EthernetType != layers.EthernetTypeIPv6 {
		t.Errorf("Ethernet type = %v, want IPv6", eth.EthernetType)
	}

	ipv6 := parsed.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if ipv6.HopLimit != 255 {
		t.Errorf("IPv6 hop limit = %d, want 255", ipv6.HopLimit)
	}
	if !ipv6.SrcIP.Equal(sourceIP) || !ipv6.DstIP.Equal(net.ParseIP("ff02::1")) {
		t.Errorf("IPv6 addresses = %s -> %s, want %s -> ff02::1", ipv6.SrcIP, ipv6.DstIP, sourceIP)
	}

	icmp := parsed.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if icmp.TypeCode.Type() != layers.ICMPv6TypeNeighborAdvertisement {
		t.Errorf("ICMPv6 type = %v, want Neighbor Advertisement", icmp.TypeCode.Type())
	}
	na := parsed.Layer(layers.LayerTypeICMPv6NeighborAdvertisement).(*layers.ICMPv6NeighborAdvertisement)
	if na.Flags != 0x20 {
		t.Errorf("NA flags = 0x%x, want Override flag 0x20", na.Flags)
	}
	if !net.IP(na.TargetAddress).Equal(c.VIP.AsSlice()) {
		t.Errorf("NA target = %s, want %s", na.TargetAddress, c.VIP)
	}
	if len(na.Options) != 1 || na.Options[0].Type != layers.ICMPv6OptTargetAddress ||
		!bytes.Equal(na.Options[0].Data, c.Iface.HardwareAddr) {
		t.Errorf("NA target link-layer option = %#v, want interface MAC", na.Options)
	}
}
