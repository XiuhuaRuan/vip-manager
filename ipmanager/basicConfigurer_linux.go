package ipmanager

import (
	"fmt"
	"net"
	"os/exec"
	"syscall"
)

var execCommand = exec.Command
var linuxSendPacketWithProtocolFn = sendPacketLinuxWithProtocol

// htons converts uint16 to network byte order
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func sendPacketLinux(iface net.Interface, packetData []byte) error {
	return sendPacketLinuxWithProtocol(iface, packetData, syscall.ETH_P_ARP)
}

func sendPacketLinuxWithProtocol(iface net.Interface, packetData []byte, protocol uint16) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	var sll syscall.SockaddrLinklayer
	sll.Protocol = htons(protocol)
	sll.Ifindex = iface.Index
	sll.Hatype = syscall.ARPHRD_ETHER
	sll.Pkttype = syscall.PACKET_HOST

	if err = syscall.Bind(fd, &sll); err != nil {
		return err
	}

	return syscall.Sendto(fd, packetData, 0, &sll)
}

func (c *BasicConfigurer) linkLocalAddress() (net.IP, error) {
	iface, err := net.InterfaceByName(c.Iface.Name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		var ip net.IP
		switch value := addr.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		}
		if ip != nil && ip.To4() == nil && ip.IsLinkLocalUnicast() {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("interface %s has no IPv6 link-local address", c.Iface.Name)
}

// configureAddress assigns virtual IP address
func (c *BasicConfigurer) configureAddress() bool {
	log.Infof("Configuring address %s on %s", c.getCIDR(), c.Iface.Name)
	result := c.runAddressConfiguration("add")
	if result {
		if c.VIP.Is6() {
			sourceIP, err := c.linkLocalAddress()
			if err != nil {
				log.Warn("Failed to find IPv6 link-local address for Neighbor Advertisement: ", err)
				return result
			}
			buff, err := c.createGratuitousNA(sourceIP)
			if err != nil {
				log.Warn("Failed to compose unsolicited Neighbor Advertisement: ", err)
			} else if err := linuxSendPacketWithProtocolFn(c.Iface, buff, syscall.ETH_P_IPV6); err != nil {
				log.Warn("Failed to send unsolicited Neighbor Advertisement: ", err)
			}
		} else {
			if buff, err := c.createGratuitousARP(); err != nil {
				log.Warn("Failed to compose gratuitous ARP request: ", err)
			} else if err := sendPacketLinux(c.Iface, buff); err != nil {
				log.Warn("Failed to send gratuitous ARP request: ", err)
			}
		}
	}

	return result
}

// deconfigureAddress drops virtual IP address
func (c *BasicConfigurer) deconfigureAddress() bool {
	log.Infof("Removing address %s on %s", c.getCIDR(), c.Iface.Name)
	return c.runAddressConfiguration("delete")
}

func (c *BasicConfigurer) runAddressConfiguration(action string) bool {
	cmd := execCommand("ip", "addr", action,
		c.getCIDR(),
		"dev", c.Iface.Name)
	output, err := cmd.CombinedOutput()

	switch err.(type) {
	case *exec.ExitError:
		log.Infof("Got error %s", output)

		return false
	}
	if err != nil {
		log.Infof("Error running ip address %s %s on %s: %s",
			action, c.VIP, c.Iface.Name, err)
		return false
	}
	return true
}
