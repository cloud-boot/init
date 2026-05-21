//go:build linux

// LUKS support for the disk-target path.
//
// When the chained distro keeps /boot INSIDE a LUKS-encrypted volume
// (full-disk encryption with GRUB 2.04+ LUKS-readable /boot, or any
// install that puts /boot on the encrypted root), cloud-boot-init
// needs to unlock the LUKS layer before opening the underlying
// filesystem. We use github.com/go-fde/luks (pure-Go LUKS1/LUKS2
// implementation) for the unlock step + adapt its *Device to
// ext4.BlockDevice so the existing OpenFromDevice path works.
//
// Limitation: this works for ext4 today. xfs/btrfs/zfs need the
// same BlockDevice/OpenFromDevice export upstream — see
// memory:userland-fs-drivers for the roadmap.
//
// Cmdline knobs:
//
//	cloudboot.disk.luks-passphrase=<pass>   passphrase for the LUKS volume.
//	                                        Should be set via metadata.url
//	                                        rather than baked into the iso
//	                                        cmdline so it doesn't leak via
//	                                        /proc/cmdline post-boot.

package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/go-fde/luks"
	fsext4 "github.com/go-filesystems/ext4"
	filesystem "github.com/go-filesystems/interface"
)

// LUKS magic strings at offset 0 of an encrypted partition.
// LUKS1: "LUKS\xba\xbe\x00\x01"
// LUKS2: "LUKS\xba\xbe\x00\x02"
var (
	luks1Magic = []byte{'L', 'U', 'K', 'S', 0xba, 0xbe, 0x00, 0x01}
	luks2Magic = []byte{'L', 'U', 'K', 'S', 0xba, 0xbe, 0x00, 0x02}
)

// detectLUKS returns true when devPath's first 8 bytes match a LUKS
// header magic. Non-fatal: I/O errors return false (the FS opener
// will surface a clearer error than a half-baked LUKS check).
func detectLUKS(devPath string) bool {
	f, err := os.Open(devPath)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [8]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		return false
	}
	return bytesEqual(hdr[:], luks1Magic) || bytesEqual(hdr[:], luks2Magic)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// luksAsBlock adapts a *luks.Device to the ext4.BlockDevice
// interface. ext4 needs Sync/Size/Truncate beyond ReadAt+WriteAt
// — for a read-only LUKS layer Sync and Truncate are no-ops /
// no-op-errors.
type luksAsBlock struct{ d *luks.Device }

func (l *luksAsBlock) ReadAt(p []byte, off int64) (int, error)  { return l.d.ReadAt(p, off) }
func (l *luksAsBlock) WriteAt(p []byte, off int64) (int, error) { return l.d.WriteAt(p, off) }
func (l *luksAsBlock) Sync() error                              { return nil }
func (l *luksAsBlock) Size() (int64, error)                     { return l.d.Size(), nil }
func (l *luksAsBlock) Truncate(int64) error {
	return errors.New("luks-on-ext4 wrapper is read-only — Truncate unsupported")
}
func (l *luksAsBlock) Close() error { return l.d.Close() }

// openLUKSExt4 unlocks the LUKS volume at devPath with `pass` and
// opens its plaintext payload as an ext4 filesystem.
func openLUKSExt4(devPath, pass string) (filesystem.Filesystem, error) {
	dev, err := luks.Open(devPath, []byte(pass))
	if err != nil {
		return nil, fmt.Errorf("luks unlock %s: %w", devPath, err)
	}
	log.Printf("luks: unlocked %s (plaintext size=%d B); opening ext4 on top", devPath, dev.Size())
	wrapped := &luksAsBlock{d: dev}
	fs, err := fsext4.OpenFromDevice(wrapped, -1)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("ext4 open over luks %s: %w", devPath, err)
	}
	return fs, nil
}

// openFSWithLUKS is openFS's LUKS-aware variant. Called from
// runDisk when detectLUKS returns true; surfaces a clear error
// when the FS opener doesn't yet support layered open or the
// operator forgot to supply a passphrase.
func openFSWithLUKS(p diskParams, devPath string, pass string) (filesystem.Filesystem, error) {
	if pass == "" {
		return nil, fmt.Errorf("disk %s is LUKS-encrypted; set cloudboot.disk.luks-passphrase= (preferably via cloudboot.metadata.url) to unlock", devPath)
	}
	switch p.FS {
	case "", "ext4":
		return openLUKSExt4(devPath, pass)
	default:
		return nil, fmt.Errorf("LUKS layering on fs=%q is not yet wired (only ext4 works today; xfs/btrfs/zfs need the same BlockDevice export upstream — see memory:userland-fs-drivers)", p.FS)
	}
}
