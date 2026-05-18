package lldp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// "Nearest bridge" group address (IEEE 802.1AB §7.1). Exposed for the linux
// transmit path; pure callers may ignore it.
var lldpMulticast = [6]byte{0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// buildLLDPDU returns the TLV stream of an LLDP frame announcing this host.
// Per 802.1AB §8 the three mandatory TLVs are Chassis ID, Port ID and TTL,
// in that order, followed by optional TLVs and a final End-of-LLDPDU.
func buildLLDPDU(iface *net.Interface, sysName, sysDesc string) []byte {
	var b []byte

	// Chassis ID TLV (type 1), subtype 4 = MAC address.
	cid := append([]byte{4}, iface.HardwareAddr...)
	b = appendTLV(b, 1, cid)

	// Port ID TLV (type 2), subtype 5 = interface name.
	pid := append([]byte{5}, []byte(iface.Name)...)
	b = appendTLV(b, 2, pid)

	// TTL TLV (type 3): 120 seconds.
	var ttl [2]byte
	binary.BigEndian.PutUint16(ttl[:], 120)
	b = appendTLV(b, 3, ttl[:])

	if sysName != "" {
		b = appendTLV(b, 5, []byte(sysName))
	}
	if sysDesc != "" {
		b = appendTLV(b, 6, []byte(sysDesc))
	}

	// End-of-LLDPDU (type 0, length 0).
	b = appendTLV(b, 0, nil)
	return b
}

func appendTLV(b []byte, ttype uint8, value []byte) []byte {
	if len(value) > 0x1FF {
		value = value[:0x1FF]
	}
	h := uint16(ttype&0x7F)<<9 | uint16(len(value))&0x1FF
	b = binary.BigEndian.AppendUint16(b, h)
	return append(b, value...)
}

func parseTLVs(payload []byte) (*Facts, error) {
	f := &Facts{}
	for i := 0; i+2 <= len(payload); {
		hdr := binary.BigEndian.Uint16(payload[i:])
		ttype := uint8(hdr >> 9)
		tlen := int(hdr & 0x1FF)
		i += 2
		if ttype == 0 { // End-of-LLDPDU
			break
		}
		if i+tlen > len(payload) {
			return nil, fmt.Errorf("truncated TLV type=%d len=%d", ttype, tlen)
		}
		v := payload[i : i+tlen]
		switch ttype {
		case 1: // Chassis ID
			if tlen >= 2 {
				f.ChassisType = v[0]
				f.ChassisID = decodeID(v[0], v[1:])
			}
		case 2: // Port ID
			if tlen >= 2 {
				f.PortType = v[0]
				f.PortID = decodeID(v[0], v[1:])
			}
		case 3: // TTL
			if tlen >= 2 {
				f.TTL = binary.BigEndian.Uint16(v)
			}
		case 4:
			f.PortDesc = string(v)
		case 5:
			f.SystemName = string(v)
		case 6:
			f.SystemDesc = string(v)
		case 7:
			if tlen >= 4 {
				f.Capabilities = binary.BigEndian.Uint16(v)
			}
		case 8: // Management address
			if tlen >= 2 {
				addrlen := int(v[0])
				if 1+addrlen <= tlen && (addrlen == 5 || addrlen == 17) {
					switch v[1] {
					case 1:
						if addrlen == 5 {
							f.MgmtAddr = net.IP(v[2 : 2+4]).String()
						}
					case 2:
						if addrlen == 17 {
							f.MgmtAddr = net.IP(v[2 : 2+16]).String()
						}
					}
				}
			}
		}
		i += tlen
	}
	return f, nil
}

func decodeID(subtype uint8, v []byte) string {
	switch subtype {
	case 3, 4: // MAC address subtypes
		if len(v) == 6 {
			return net.HardwareAddr(v).String()
		}
	}
	return string(v)
}
