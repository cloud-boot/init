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
	fsbtrfs "github.com/go-filesystems/btrfs"
	fsext4 "github.com/go-filesystems/ext4"
	filesystem "github.com/go-filesystems/interface"
	fsxfs "github.com/go-filesystems/xfs"
	fszfs "github.com/go-filesystems/zfs"
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

// luksAsZFSBackend is the BlockBackend-flavoured twin of
// luksAsBlock — same wrap, different interface (ext4 and zfs
// libs each define their own block-backend type, but the
// method set is identical).
type luksAsZFSBackend struct{ d *luks.Device }

func (l *luksAsZFSBackend) ReadAt(p []byte, off int64) (int, error)  { return l.d.ReadAt(p, off) }
func (l *luksAsZFSBackend) WriteAt(p []byte, off int64) (int, error) { return l.d.WriteAt(p, off) }
func (l *luksAsZFSBackend) Sync() error                              { return nil }
func (l *luksAsZFSBackend) Size() (int64, error)                     { return l.d.Size(), nil }
func (l *luksAsZFSBackend) Truncate(int64) error {
	return errors.New("luks-on-zfs wrapper is read-only — Truncate unsupported")
}
func (l *luksAsZFSBackend) Close() error { return l.d.Close() }

// openLUKSZFS unlocks the LUKS volume and opens a ZFS pool on
// top of its plaintext, optionally navigating to a nested
// dataset (e.g. "ROOT/pve-1").
func openLUKSZFS(devPath, pass, datasetPath string) (filesystem.Filesystem, error) {
	dev, err := luks.Open(devPath, []byte(pass))
	if err != nil {
		return nil, fmt.Errorf("luks unlock %s: %w", devPath, err)
	}
	log.Printf("luks: unlocked %s (plaintext size=%d B); opening zfs on top (dataset=%q)",
		devPath, dev.Size(), datasetPath)
	wrapped := &luksAsZFSBackend{d: dev}
	fs, err := fszfs.OpenFromDeviceDataset(wrapped, -1, datasetPath)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("zfs open over luks %s: %w", devPath, err)
	}
	return fs, nil
}

// luksAsXFSBackend / luksAsBTRFSBackend are the xfs.BlockBackend
// and btrfs.BlockBackend twins of luksAsBlock. Each go-filesystems/*
// lib defines its own block-backend type — the method set is
// identical, only the type identity differs. Each adapter is a
// thin shim around a *luks.Device.
type luksAsXFSBackend struct{ d *luks.Device }

func (l *luksAsXFSBackend) ReadAt(p []byte, off int64) (int, error)  { return l.d.ReadAt(p, off) }
func (l *luksAsXFSBackend) WriteAt(p []byte, off int64) (int, error) { return l.d.WriteAt(p, off) }
func (l *luksAsXFSBackend) Sync() error                              { return nil }
func (l *luksAsXFSBackend) Size() (int64, error)                     { return l.d.Size(), nil }
func (l *luksAsXFSBackend) Truncate(int64) error {
	return errors.New("luks-on-xfs wrapper is read-only — Truncate unsupported")
}
func (l *luksAsXFSBackend) Close() error { return l.d.Close() }

type luksAsBTRFSBackend struct{ d *luks.Device }

func (l *luksAsBTRFSBackend) ReadAt(p []byte, off int64) (int, error) { return l.d.ReadAt(p, off) }
func (l *luksAsBTRFSBackend) WriteAt(p []byte, off int64) (int, error) {
	return l.d.WriteAt(p, off)
}
func (l *luksAsBTRFSBackend) Sync() error          { return nil }
func (l *luksAsBTRFSBackend) Size() (int64, error) { return l.d.Size(), nil }
func (l *luksAsBTRFSBackend) Truncate(int64) error {
	return errors.New("luks-on-btrfs wrapper is read-only — Truncate unsupported")
}
func (l *luksAsBTRFSBackend) Close() error { return l.d.Close() }

// openLUKSXFS unlocks the LUKS volume and opens an XFS filesystem
// on top of its plaintext.
func openLUKSXFS(devPath, pass string) (filesystem.Filesystem, error) {
	dev, err := luks.Open(devPath, []byte(pass))
	if err != nil {
		return nil, fmt.Errorf("luks unlock %s: %w", devPath, err)
	}
	log.Printf("luks: unlocked %s (plaintext size=%d B); opening xfs on top", devPath, dev.Size())
	wrapped := &luksAsXFSBackend{d: dev}
	fs, err := fsxfs.OpenFromDevice(wrapped, -1)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("xfs open over luks %s: %w", devPath, err)
	}
	return fs, nil
}

// openLUKSBtrfs unlocks the LUKS volume and opens a btrfs filesystem
// on top of its plaintext.
func openLUKSBtrfs(devPath, pass string) (filesystem.Filesystem, error) {
	dev, err := luks.Open(devPath, []byte(pass))
	if err != nil {
		return nil, fmt.Errorf("luks unlock %s: %w", devPath, err)
	}
	log.Printf("luks: unlocked %s (plaintext size=%d B); opening btrfs on top", devPath, dev.Size())
	wrapped := &luksAsBTRFSBackend{d: dev}
	fs, err := fsbtrfs.OpenFromDevice(wrapped, -1)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("btrfs open over luks %s: %w", devPath, err)
	}
	return fs, nil
}

// openFSWithLUKS is openFS's LUKS-aware variant. Called from
// runDisk when detectLUKS returns true.
func openFSWithLUKS(p diskParams, devPath string, pass string) (filesystem.Filesystem, error) {
	if pass == "" {
		return nil, fmt.Errorf("disk %s is LUKS-encrypted; set cloudboot.disk.luks-passphrase= (preferably via cloudboot.metadata.url) to unlock", devPath)
	}
	switch p.FS {
	case "", "ext4":
		return openLUKSExt4(devPath, pass)
	case "xfs":
		return openLUKSXFS(devPath, pass)
	case "btrfs":
		return openLUKSBtrfs(devPath, pass)
	case "zfs":
		// For ZFS-on-LUKS, p.Device carries the dataset name
		// ("rpool/ROOT/pve-1"). We split off the pool prefix —
		// the LUKS layer is one physical block device; the
		// dataset is selected post-decryption.
		_, dataset := splitPoolAndDataset(p.Device)
		return openLUKSZFS(devPath, pass, dataset)
	default:
		return nil, fmt.Errorf("LUKS layering on fs=%q is not yet wired (ext4/xfs/btrfs/zfs supported today)", p.FS)
	}
}
