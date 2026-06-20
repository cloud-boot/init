//go:build linux

// Btrfs multi-device discovery for the disk-target path.
//
// A btrfs filesystem can span multiple block devices (RAID0 / RAID1 /
// RAID10 / RAID5 / RAID6, plus DUP within a single device). All legs
// share the same on-disk fsid stored in the superblock at offset 0x20.
// The single-device opener handles SINGLE/DUP/RAID1 (via dev_item.devid
// stripe matching) but RAID0/10/5/6 need every data-bearing leg to be
// opened together — see go-filesystems/btrfs.OpenFromDevices.
//
// findBtrfsLegs reads the primary device's superblock to learn its fsid,
// then walks /sys/block (via listWholeDisks) to find every other device
// whose superblock fsid matches. Returns the full list with the primary
// first (OpenFromDevices uses devs[0] as the primary).

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
)

// btrfsFileBackend adapts *os.File to fsbtrfs.BlockBackend. Mirrors the
// existing osFileBackend pattern in the upstream lib but stays local so
// cloud-boot-init owns the file handle (one per leg of the multi-device
// pool). Reads / writes / Sync / Truncate / Size / Close delegate to
// *os.File; the lib's pool dedupes Close calls so passing the same
// backend twice (we don't) wouldn't double-close.
type btrfsFileBackend struct{ f *os.File }

func (o *btrfsFileBackend) ReadAt(p []byte, off int64) (int, error)  { return o.f.ReadAt(p, off) }
func (o *btrfsFileBackend) WriteAt(p []byte, off int64) (int, error) { return o.f.WriteAt(p, off) }
func (o *btrfsFileBackend) Sync() error                              { return o.f.Sync() }
func (o *btrfsFileBackend) Truncate(size int64) error                { return o.f.Truncate(size) }
func (o *btrfsFileBackend) Close() error                             { return o.f.Close() }
func (o *btrfsFileBackend) Size() (int64, error) {
	fi, err := o.f.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// btrfsMagic itself is declared in disk_resolve.go (as a string).
// We reuse it via []byte conversion below — same on-disk value
// "_BHRfS_M" at superblock offset 0x40 (sb starts at byte 0x10000).

// findBtrfsLegs returns all block devices belonging to the same btrfs
// pool as `primary`, starting with `primary` itself. The lookup matches
// on the 16-byte fsid stored in the superblock at byte offset 0x20.
//
// Returns just []{primary} when no other matching legs are found
// (single-device install or other legs not present in the VM).
// Reading-side errors on candidate devices are logged and skipped —
// they're not fatal for the discovery (lots of devices in a VM are
// removable / unreadable; we just want to find ones that match).
func findBtrfsLegs(primary string) ([]string, error) {
	primaryFsid, err := readBtrfsFsid(primary)
	if err != nil {
		return nil, fmt.Errorf("btrfs leg discovery: read primary fsid from %s: %w", primary, err)
	}
	legs := []string{primary}
	candidates, err := listWholeDisks()
	if err != nil {
		log.Printf("btrfs leg discovery: listWholeDisks failed (%v); proceeding with primary only", err)
		return legs, nil
	}
	for _, dev := range candidates {
		if dev == primary {
			continue
		}
		fsid, err := readBtrfsFsid(dev)
		if err != nil {
			// Non-btrfs device, removed media, etc. — skip silently.
			continue
		}
		if bytes.Equal(fsid, primaryFsid) {
			log.Printf("btrfs leg discovery: %s matches primary fsid (sibling leg)", dev)
			legs = append(legs, dev)
		}
	}
	return legs, nil
}

// readBtrfsFsid pulls the 16-byte fsid out of a candidate device's
// btrfs superblock. Returns an error when the magic doesn't match — the
// caller treats that as "not a btrfs device, skip".
func readBtrfsFsid(devPath string) ([]byte, error) {
	f, err := os.Open(devPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var hdr [80]byte // covers fsid (0x20–0x30) + magic (0x40–0x48)
	if _, err := f.ReadAt(hdr[:], 0x10000); err != nil {
		return nil, err
	}
	if string(hdr[64:72]) != btrfsMagic {
		return nil, fmt.Errorf("%s: not a btrfs device (magic mismatch at sb+0x40)", devPath)
	}
	out := make([]byte, 16)
	copy(out, hdr[32:48])
	return out, nil
}
