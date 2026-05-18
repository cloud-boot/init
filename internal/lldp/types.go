// Package lldp captures and emits IEEE 802.1AB Link Layer Discovery Protocol
// frames. RX gives cloud-boot-init visibility into the upstream switch (chassis,
// port, system name) so plans can make rack/port-aware decisions. TX advertises
// the booting host to the network for inventory purposes.
//
// All wire-level I/O lives in the Linux build (AF_PACKET); other platforms get
// a no-op stub so the package can still be imported from host tools.
package lldp

// EtherType is the IEEE-assigned LLDP EtherType.
const EtherType uint16 = 0x88CC

// Facts is the decoded subset of a single LLDPDU we care about.
type Facts struct {
	ChassisType  uint8  // LLDP "chassis ID subtype"
	ChassisID    string // human form of the chassis ID (MAC if subtype 4)
	PortType     uint8  // LLDP "port ID subtype"
	PortID       string // human form of the port ID (iface name if subtype 5)
	TTL          uint16 // advertised TTL seconds
	SystemName   string // sysName MIB
	SystemDesc   string // sysDescr MIB
	PortDesc     string // ifDescr MIB
	Capabilities uint16 // see 802.1AB §8.5.8
	MgmtAddr     string // first management address (v4 or v6)
}
