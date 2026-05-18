//go:build linux

package lldp

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// Listen opens an AF_PACKET socket on ifaceName, blocks for up to timeout
// waiting for a single LLDP frame, then returns the decoded Facts.
//
// SOCK_DGRAM strips the Ethernet header on RX so the caller gets just the
// LLDPDU TLV stream.
func Listen(ifaceName string, timeout time.Duration) (*Facts, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("iface %s: %w", ifaceName, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(EtherType)))
	if err != nil {
		return nil, fmt.Errorf("open AF_PACKET: %w", err)
	}
	defer unix.Close(fd)

	sll := &unix.SockaddrLinklayer{
		Protocol: htons(EtherType),
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, sll); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}
	tv := unix.Timeval{Sec: int64(timeout / time.Second), Usec: int64((timeout % time.Second) / time.Microsecond)}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, fmt.Errorf("set rcvtimeo: %w", err)
	}

	buf := make([]byte, 1600)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("recv: %w", err)
	}
	return parseTLVs(buf[:n])
}

// Send emits a single LLDP frame from ifaceName announcing this host. The
// kernel prepends the Ethernet header from sockaddr_ll so the caller need
// only construct the LLDPDU TLV stream.
func Send(ifaceName, systemName, systemDesc string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("iface %s: %w", ifaceName, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(EtherType)))
	if err != nil {
		return fmt.Errorf("open AF_PACKET: %w", err)
	}
	defer unix.Close(fd)

	payload := buildLLDPDU(iface, systemName, systemDesc)
	sll := &unix.SockaddrLinklayer{
		Protocol: htons(EtherType),
		Ifindex:  iface.Index,
		Halen:    6,
	}
	copy(sll.Addr[:6], lldpMulticast[:])
	return unix.Sendto(fd, payload, 0, sll)
}
