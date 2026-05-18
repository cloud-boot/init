package lldp

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestHtons(t *testing.T) {
	if got := htons(0x1234); got != 0x3412 {
		t.Errorf("htons = 0x%x", got)
	}
}

func TestBuildAndParse_RoundTrip(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:00:00:00:42")
	iface := &net.Interface{Name: "eth0", HardwareAddr: mac}
	payload := buildLLDPDU(iface, "sw-rack-3", "ToR switch")

	// Tail must be the End-of-LLDPDU TLV (2 bytes of 0).
	if len(payload) < 2 || payload[len(payload)-2] != 0 || payload[len(payload)-1] != 0 {
		t.Fatalf("missing End-of-LLDPDU terminator: %x", payload)
	}

	f, err := parseTLVs(payload)
	if err != nil {
		t.Fatalf("parseTLVs: %v", err)
	}
	if f.ChassisID != mac.String() {
		t.Errorf("ChassisID = %q, want %q", f.ChassisID, mac.String())
	}
	if f.PortID != "eth0" {
		t.Errorf("PortID = %q", f.PortID)
	}
	if f.TTL != 120 {
		t.Errorf("TTL = %d", f.TTL)
	}
	if f.SystemName != "sw-rack-3" {
		t.Errorf("SystemName = %q", f.SystemName)
	}
	if f.SystemDesc != "ToR switch" {
		t.Errorf("SystemDesc = %q", f.SystemDesc)
	}
}

func TestBuild_OmitsEmptyOptionals(t *testing.T) {
	iface := &net.Interface{Name: "x", HardwareAddr: make(net.HardwareAddr, 6)}
	p := buildLLDPDU(iface, "", "")
	f, err := parseTLVs(p)
	if err != nil {
		t.Fatal(err)
	}
	if f.SystemName != "" || f.SystemDesc != "" {
		t.Errorf("unexpected optional TLVs decoded: %+v", f)
	}
}

func TestAppendTLV_LongValueTruncated(t *testing.T) {
	big := bytes.Repeat([]byte{'A'}, 0x200) // 512 > 0x1FF
	b := appendTLV(nil, 5, big)
	if len(b) != 2+0x1FF {
		t.Errorf("expected 2+0x1FF bytes, got %d", len(b))
	}
	hdr := binary.BigEndian.Uint16(b[:2])
	if int(hdr&0x1FF) != 0x1FF {
		t.Errorf("encoded length = %d, want 0x1FF", hdr&0x1FF)
	}
}

func TestParseTLVs_TruncatedTLV(t *testing.T) {
	// Type=4 (Port description), Length=10, but only 4 bytes follow.
	hdr := uint16(4)<<9 | 10
	b := make([]byte, 2+4)
	binary.BigEndian.PutUint16(b, hdr)
	if _, err := parseTLVs(b); err == nil {
		t.Fatal("expected truncated-TLV error")
	}
}

func TestParseTLVs_EmptyPayload(t *testing.T) {
	f, err := parseTLVs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if (*f) != (Facts{}) {
		t.Errorf("expected zero Facts, got %+v", f)
	}
}

func TestParseTLVs_AllTypes(t *testing.T) {
	var p []byte
	// Chassis ID subtype 4 (MAC).
	mac := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	p = appendTLV(p, 1, append([]byte{4}, mac...))
	// Port ID subtype 3 (MAC) → tests decodeID's other MAC branch.
	p = appendTLV(p, 2, append([]byte{3}, mac...))
	// TTL.
	ttl := []byte{0x00, 0x3C} // 60s
	p = appendTLV(p, 3, ttl)
	// Port description (type 4).
	p = appendTLV(p, 4, []byte("port-1"))
	// System name + description.
	p = appendTLV(p, 5, []byte("name"))
	p = appendTLV(p, 6, []byte("desc"))
	// Capabilities.
	caps := []byte{0x00, 0x14, 0x00, 0x14}
	p = appendTLV(p, 7, caps)
	// Management address v4 (addrlen=5: 1 byte family + 4 bytes IP).
	mgmt4 := []byte{5, 1, 10, 0, 0, 1}
	p = appendTLV(p, 8, mgmt4)
	// End-of-LLDPDU.
	p = appendTLV(p, 0, nil)

	f, err := parseTLVs(p)
	if err != nil {
		t.Fatal(err)
	}
	if f.ChassisID != "de:ad:be:ef:00:01" || f.PortID != "de:ad:be:ef:00:01" {
		t.Errorf("MAC parsing: %+v", f)
	}
	if f.TTL != 60 || f.PortDesc != "port-1" || f.SystemName != "name" || f.SystemDesc != "desc" {
		t.Errorf("string TLVs: %+v", f)
	}
	if f.Capabilities != 0x0014 {
		t.Errorf("capabilities: %#x", f.Capabilities)
	}
	if f.MgmtAddr != "10.0.0.1" {
		t.Errorf("mgmt v4: %q", f.MgmtAddr)
	}
}

func TestParseTLVs_MgmtAddrV6(t *testing.T) {
	v6 := net.ParseIP("fe80::1")
	mgmt6 := append([]byte{17, 2}, v6.To16()...)
	p := appendTLV(nil, 8, mgmt6)
	p = appendTLV(p, 0, nil)
	f, err := parseTLVs(p)
	if err != nil {
		t.Fatal(err)
	}
	if f.MgmtAddr != "fe80::1" {
		t.Errorf("mgmt v6: %q", f.MgmtAddr)
	}
}

func TestParseTLVs_MgmtAddrUnsupportedFamily(t *testing.T) {
	// addrlen=5 (v4 size) but family byte = 99 (unknown).
	bad := []byte{5, 99, 1, 2, 3, 4}
	p := appendTLV(nil, 8, bad)
	p = appendTLV(p, 0, nil)
	f, err := parseTLVs(p)
	if err != nil {
		t.Fatal(err)
	}
	if f.MgmtAddr != "" {
		t.Errorf("unexpected MgmtAddr: %q", f.MgmtAddr)
	}
}

func TestParseTLVs_MgmtAddrWrongLength(t *testing.T) {
	// addrlen=9 (not 5 or 17) — entire mgmt TLV silently skipped.
	bad := []byte{9, 1, 1, 2, 3, 4, 5, 6, 7, 8}
	p := appendTLV(nil, 8, bad)
	p = appendTLV(p, 0, nil)
	f, _ := parseTLVs(p)
	if f.MgmtAddr != "" {
		t.Errorf("unexpected MgmtAddr: %q", f.MgmtAddr)
	}
}

func TestParseTLVs_IgnoresUnknownType(t *testing.T) {
	// Type 100 is in the standard-but-unknown range — should be skipped.
	p := appendTLV(nil, 100, []byte("blob"))
	p = appendTLV(p, 5, []byte("sys")) // ensure parser keeps going
	p = appendTLV(p, 0, nil)
	f, err := parseTLVs(p)
	if err != nil {
		t.Fatal(err)
	}
	if f.SystemName != "sys" {
		t.Errorf("post-unknown parsing lost: %+v", f)
	}
}

func TestDecodeID_NonMACSubtype(t *testing.T) {
	// Subtype 7 (locally assigned) → returns raw string.
	if got := decodeID(7, []byte("locally")); got != "locally" {
		t.Errorf("decodeID subtype 7 = %q", got)
	}
}

func TestParseTLVs_ShortChassisAndPort(t *testing.T) {
	// Length=1 TLVs (tlen<2) drop into the no-op branch.
	p := appendTLV(nil, 1, []byte{4})
	p = appendTLV(p, 2, []byte{5})
	p = appendTLV(p, 3, []byte{0}) // ttl tlen<2
	p = appendTLV(p, 7, []byte{0}) // caps tlen<4
	p = appendTLV(p, 0, nil)
	f, err := parseTLVs(p)
	if err != nil {
		t.Fatal(err)
	}
	if f.ChassisID != "" || f.PortID != "" || f.TTL != 0 || f.Capabilities != 0 {
		t.Errorf("short TLVs leaked: %+v", f)
	}
}

func TestParseTLVs_MgmtAddrShortTLV(t *testing.T) {
	// Length=1 → tlen<2 path silently skips management address.
	p := appendTLV(nil, 8, []byte{0})
	p = appendTLV(p, 0, nil)
	f, err := parseTLVs(p)
	if err != nil {
		t.Fatal(err)
	}
	if f.MgmtAddr != "" {
		t.Errorf("expected empty MgmtAddr, got %q", f.MgmtAddr)
	}
}
