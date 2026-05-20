package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// fakePartition writes a 1 MiB file with a hand-crafted superblock for
// the requested filesystem flavour. Returns the path. Each layout
// matches the constants used by disk_resolve_linux.go's probe funcs.
func fakePartition(t *testing.T, name, fsType, label, uuidHex string) string {
	t.Helper()
	const size = 1 << 20
	path := filepath.Join(t.TempDir(), name)
	buf := make([]byte, size)
	if len(uuidHex) != 32 {
		t.Fatalf("uuidHex must be 32 hex chars (no dashes), got %q", uuidHex)
	}
	uuid := make([]byte, 16)
	for i := 0; i < 16; i++ {
		var b byte
		if _, err := fmt.Sscanf(uuidHex[i*2:i*2+2], "%02x", &b); err != nil {
			t.Fatal(err)
		}
		uuid[i] = b
	}
	switch fsType {
	case "ext4":
		// magic at 1024+56, uuid at 1024+104, label at 1024+120
		binary.LittleEndian.PutUint16(buf[1024+56:1024+58], 0xEF53)
		copy(buf[1024+104:1024+120], uuid)
		copy(buf[1024+120:1024+136], []byte(label))
	case "xfs":
		// magic "XFSB" at offset 0; uuid at 32; label at 108
		copy(buf[0:4], []byte("XFSB"))
		copy(buf[32:48], uuid)
		copy(buf[108:120], []byte(label))
	case "btrfs":
		// SB at 65536. Magic "_BHRfS_M" at sb+64, uuid at sb+32, label at sb+299.
		copy(buf[65536+64:65536+72], []byte("_BHRfS_M"))
		copy(buf[65536+32:65536+48], uuid)
		copy(buf[65536+299:65536+299+len(label)], []byte(label))
	default:
		t.Fatalf("unknown fsType %q", fsType)
	}
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadFSLabel_Ext(t *testing.T) {
	p := fakePartition(t, "ext.img", "ext4", "rootfs", "0123456789abcdef0123456789abcdef")
	s, err := readFSLabel(p)
	if err != nil || s == nil {
		t.Fatalf("ext: got (%v, %v)", s, err)
	}
	if s.fsType != "ext4" || s.label != "rootfs" {
		t.Errorf("ext: got %+v", s)
	}
	if s.uuid != "01234567-89ab-cdef-0123-456789abcdef" {
		t.Errorf("ext uuid: got %s", s.uuid)
	}
}

func TestReadFSLabel_Xfs(t *testing.T) {
	p := fakePartition(t, "xfs.img", "xfs", "almaboot", "17dc27c645584e4c8bcd386c73057ae5")
	s, err := readFSLabel(p)
	if err != nil || s == nil {
		t.Fatalf("xfs: got (%v, %v)", s, err)
	}
	if s.fsType != "xfs" || s.label != "almaboot" {
		t.Errorf("xfs: got %+v", s)
	}
	if s.uuid != "17dc27c6-4558-4e4c-8bcd-386c73057ae5" {
		t.Errorf("xfs uuid: got %s", s.uuid)
	}
}

func TestReadFSLabel_Btrfs(t *testing.T) {
	p := fakePartition(t, "btrfs.img", "btrfs", "ROOT", "60441db91fb2c01407f910c8b6fda8f7")
	s, err := readFSLabel(p)
	if err != nil || s == nil {
		t.Fatalf("btrfs: got (%v, %v)", s, err)
	}
	if s.fsType != "btrfs" || s.label != "ROOT" {
		t.Errorf("btrfs: got %+v", s)
	}
	if s.uuid != "60441db9-1fb2-c014-07f9-10c8b6fda8f7" {
		t.Errorf("btrfs uuid: got %s", s.uuid)
	}
}

func TestReadFSLabel_Unknown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blank.img")
	if err := os.WriteFile(path, make([]byte, 1<<20), 0644); err != nil {
		t.Fatal(err)
	}
	s, err := readFSLabel(path)
	if err != nil || s != nil {
		t.Fatalf("blank: expected (nil,nil); got (%v,%v)", s, err)
	}
}
