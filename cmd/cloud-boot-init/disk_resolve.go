// Cross-platform filesystem superblock probes used by the Linux-only
// resolver in disk_resolve_linux.go. Lives here (no build tag) so the
// table-driven tests for ext / xfs / btrfs superblock parsing run on
// every host — they craft byte arrays and feed them straight in,
// without touching /proc/partitions or GPT.

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// fsLabel is the normalised view of a partition's identifying
// metadata. fsType is a free-form tag used by the diagnostic trail
// findFS prints when no match is found.
type fsLabel struct {
	label, uuid, fsType string
}

// readFSLabel tries every filesystem layout we recognise and returns
// the first match. nil, nil means "no recognisable superblock here" —
// the caller skips the device silently. A non-nil error is reserved
// for genuine I/O problems (open / seek / short read).
func readFSLabel(path string) (*fsLabel, error) {
	if s, err := readExtSuper(path); err != nil {
		return nil, err
	} else if s != nil {
		return &fsLabel{label: s.label(), uuid: s.uuid(), fsType: "ext4"}, nil
	}
	if s, err := readXfsSuper(path); err != nil {
		return nil, err
	} else if s != nil {
		return &fsLabel{label: s.label, uuid: s.uuid, fsType: "xfs"}, nil
	}
	if s, err := readBtrfsSuper(path); err != nil {
		return nil, err
	} else if s != nil {
		return &fsLabel{label: s.label, uuid: s.uuid, fsType: "btrfs"}, nil
	}
	return nil, nil
}

// formatUUID16 prints a 16-byte UUID as RFC-4122 hex. ext4 / xfs /
// btrfs all store UUIDs in raw on-disk byte order — this format
// matches what blkid prints + what most distro cmdlines use.
func formatUUID16(b []byte) string {
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// ─── ext{2,3,4} ───────────────────────────────────────────────────────

const (
	extSuperOff   = 1024
	extMagicAt    = 56 // bytes into the superblock
	extUUIDAt     = 104
	extLabelAt    = 120
	extMagicValue = 0xEF53
)

type extSuper struct {
	uuidBytes  [16]byte
	labelBytes [16]byte
}

func (s *extSuper) label() string {
	return string(bytes.TrimRight(s.labelBytes[:], "\x00"))
}

func (s *extSuper) uuid() string {
	return formatUUID16(s.uuidBytes[:])
}

func readExtSuper(path string) (*extSuper, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var buf [256]byte
	if _, err := f.Seek(extSuperOff, io.SeekStart); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(f, buf[:]); err != nil {
		// Tolerate short partitions (anything that's smaller than the
		// ext4 superblock can't be an ext4 fs; skip silently like a
		// magic miss).
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	if binary.LittleEndian.Uint16(buf[extMagicAt:extMagicAt+2]) != extMagicValue {
		return nil, nil
	}
	s := &extSuper{}
	copy(s.uuidBytes[:], buf[extUUIDAt:extUUIDAt+16])
	copy(s.labelBytes[:], buf[extLabelAt:extLabelAt+16])
	return s, nil
}

// ─── xfs ──────────────────────────────────────────────────────────────
//
// xfs superblock at offset 0; magic "XFSB" (BE ASCII), uuid at +32 (16
// bytes), label at +108 (12 ASCII bytes, NUL-padded).

const (
	xfsSuperOff  = 0
	xfsMagicAt   = 0
	xfsUUIDAt    = 32
	xfsLabelAt   = 108
	xfsMagicBE   = "XFSB"
	xfsLabelSize = 12
)

type xfsSuper struct {
	label, uuid string
}

func readXfsSuper(path string) (*xfsSuper, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var buf [256]byte
	if _, err := f.Seek(xfsSuperOff, io.SeekStart); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(f, buf[:]); err != nil {
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	if string(buf[xfsMagicAt:xfsMagicAt+4]) != xfsMagicBE {
		return nil, nil
	}
	s := &xfsSuper{}
	s.label = string(bytes.TrimRight(buf[xfsLabelAt:xfsLabelAt+xfsLabelSize], "\x00"))
	s.uuid = formatUUID16(buf[xfsUUIDAt : xfsUUIDAt+16])
	return s, nil
}

// ─── btrfs ────────────────────────────────────────────────────────────
//
// btrfs primary superblock at offset 65536. Magic "_BHRfS_M" (8 bytes
// LE) at sb+64. UUID at sb+32. Label at sb+299 (256 bytes ASCII, NUL-
// padded). Secondary copies at 64 MiB / 256 GiB exist but we only
// need the primary for label resolution.

const (
	btrfsSuperOff  = 65536
	btrfsMagicAt   = 64
	btrfsUUIDAt    = 32
	btrfsLabelAt   = 299
	btrfsLabelSize = 256
	btrfsMagic     = "_BHRfS_M"
)

type btrfsSuper struct {
	label, uuid string
}

func readBtrfsSuper(path string) (*btrfsSuper, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	const need = btrfsLabelAt + btrfsLabelSize
	var buf [need]byte
	if _, err := f.Seek(btrfsSuperOff, io.SeekStart); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(f, buf[:]); err != nil {
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	if string(buf[btrfsMagicAt:btrfsMagicAt+len(btrfsMagic)]) != btrfsMagic {
		return nil, nil
	}
	s := &btrfsSuper{}
	s.label = string(bytes.TrimRight(buf[btrfsLabelAt:btrfsLabelAt+btrfsLabelSize], "\x00"))
	s.uuid = formatUUID16(buf[btrfsUUIDAt : btrfsUUIDAt+16])
	return s, nil
}
