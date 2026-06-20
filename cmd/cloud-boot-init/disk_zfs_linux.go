//go:build linux

// ZFS-on-root branch of the disk target path.
//
// Reads /boot/vmlinuz + /boot/initrd from a ZFS-rooted distro
// install (Proxmox VE, Ubuntu Server ZSYS, …) using a pure-Go
// userland driver — no kernel ZFS module, no zpool/zfs binaries,
// no CDDL out-of-tree compile. The driver lives in the sibling
// `github.com/go-filesystems/zfs` package, which navigates the
// pool's DSL tree and reads ZPL files directly from the raw
// block device.
//
// Architectural consequence vs an in-kernel ZFS driver:
//
//   * We can drop CONFIG_ZFS / OpenZFS module bundling entirely.
//     The bootstrap kernel needs no ZFS support at all — only
//     virtio-blk to expose the raw vdev as /dev/vdN.
//   * We don't `mount(2)` anything for the ZFS path; the Go FS
//     interface returns the file bytes directly. runDiskMounted
//     still drives the kernel+initrd kexec, but the files come
//     from /run/cloud-boot/<staged> rather than /mnt/boot.
//   * Single-vdev pools only (the library doesn't yet handle
//     RAID-Z parity reconstruction). Covers Proxmox SSD-only
//     installs; multi-vdev RAID-Z is roadmap.
//
// Cmdline / plan schema unchanged from the kernel-module
// proposal: target's Disk.Device is the dataset path
// (e.g. "rpool/ROOT/pve-1"), Disk.FS = "zfs", Disk.Kernel /
// Disk.Initrd are paths inside that dataset's filesystem
// view ("/boot/vmlinuz-pve" etc.). The first path segment
// of Disk.Device is treated as the pool name (so the library
// knows where it should land) and stripped before traversal.
//
// See memory:zfs-root-support for the broader design.

package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	filesystem "github.com/go-filesystems/interface"
	fszfs "github.com/go-filesystems/zfs"
)

// zfsFileBackend adapts *os.File to fszfs.BlockBackend, the per-leg
// backing interface OpenFromDevices expects. cloud-boot-init owns
// the file handles (one per leg); the lib's pool dedupes Close calls
// so the same backend appearing twice would not double-close.
type zfsFileBackend struct{ f *os.File }

func (o *zfsFileBackend) ReadAt(p []byte, off int64) (int, error)  { return o.f.ReadAt(p, off) }
func (o *zfsFileBackend) WriteAt(p []byte, off int64) (int, error) { return o.f.WriteAt(p, off) }
func (o *zfsFileBackend) Sync() error                              { return o.f.Sync() }
func (o *zfsFileBackend) Truncate(size int64) error                { return o.f.Truncate(size) }
func (o *zfsFileBackend) Close() error                             { return o.f.Close() }
func (o *zfsFileBackend) Size() (int64, error) {
	fi, err := o.f.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// runDiskZFS handles the fs="zfs" branch of a Disk target.
//
// Steps:
//
//	1. Resolve the BLOCK device that hosts the pool. The plan's
//	   Disk.Device is "<pool>/<dataset...>"; cloud-boot can't know
//	   which physical device that maps to without a directory scan.
//	   The pool's vdev label sits at byte 0 of one of the attached
//	   virtio-blk devices; we walk /sys/block and probe each.
//	2. Open the dataset via fszfs.OpenDataset(devPath, -1, path).
//	3. Read Disk.Kernel + Disk.Initrd via the FS interface, stage
//	   them under downloadDir as regular files.
//	4. Hand off to runDiskMounted via a small adapter — set
//	   p.Kernel + p.Initrd to the staged paths and clear p.Device
//	   so the existing flow doesn't try a kernel mount(2).
func runDiskZFS(p diskParams) error {
	// Disk.Device convention for ZFS: "<pool>/<rest>" or just
	// "<pool>" for the pool root.
	pool, datasetPath := splitPoolAndDataset(p.Device)
	if pool == "" {
		return fmt.Errorf("zfs target: device %q must be a dataset path (e.g. rpool/ROOT/pve-1)", p.Device)
	}

	legs, err := findZFSVdevs(pool)
	if err != nil {
		return fmt.Errorf("zfs target %q: locating vdev for pool %q: %w", p.Device, pool, err)
	}
	log.Printf("zfs: pool %q found on %v; opening dataset %q", pool, legs, datasetPath)

	var fs filesystem.Filesystem
	if len(legs) == 1 {
		// Single-vdev (or single-leg mirror open). Use the single-
		// device path — cheaper and avoids spinning up the multi-
		// vdev pool wrapper.
		fs, err = fszfs.OpenDataset(legs[0], -1, datasetPath)
		if err != nil {
			return fmt.Errorf("zfs open %s (dataset %q): %w", legs[0], datasetPath, err)
		}
	} else {
		// Multi-vdev (mirror with explicit all-leg open, or
		// raidz1/2/3). Wrap each leg in an osFileBackend and feed
		// to OpenFromDevices in vdev-id order.
		backends := make([]fszfs.BlockBackend, 0, len(legs))
		for _, leg := range legs {
			f, oerr := os.OpenFile(leg, os.O_RDWR, 0o600)
			if oerr != nil {
				for _, b := range backends {
					b.Close()
				}
				return fmt.Errorf("zfs open leg %s: %w", leg, oerr)
			}
			backends = append(backends, &zfsFileBackend{f: f})
		}
		fs, err = fszfs.OpenFromDevices(backends, -1, datasetPath)
		if err != nil {
			return fmt.Errorf("zfs OpenFromDevices (%d legs, dataset %q): %w", len(legs), datasetPath, err)
		}
	}
	defer fs.Close()

	if p.Kernel == "" {
		return fmt.Errorf("zfs target %q: disk.kernel= must be set (the library can't pick newest /boot/vmlinuz-* on its own)", p.Device)
	}
	if p.Initrd == "" {
		return fmt.Errorf("zfs target %q: disk.initrd= must be set", p.Device)
	}

	kBytes, err := fs.ReadFile(p.Kernel)
	if err != nil {
		return fmt.Errorf("zfs read %s%s: %w", datasetPath, p.Kernel, err)
	}
	iBytes, err := fs.ReadFile(p.Initrd)
	if err != nil {
		return fmt.Errorf("zfs read %s%s: %w", datasetPath, p.Initrd, err)
	}

	// Stage extracted bytes under downloadDir; kexecStaged loads
	// them and hands off. Pure-Go path, no /mnt anywhere.
	kStaged, iStaged, err := stageBootBytes(kBytes, iBytes)
	if err != nil {
		return err
	}
	log.Printf("zfs: staged kernel=%d bytes initrd=%d bytes; kexec'ing", len(kBytes), len(iBytes))
	return kexecStaged(p, kStaged, iStaged)
}

// splitPoolAndDataset breaks "rpool/ROOT/pve-1" into ("rpool",
// "ROOT/pve-1") so the pool name informs vdev discovery while
// the dataset path goes to OpenDataset.
func splitPoolAndDataset(devicePath string) (pool, dataset string) {
	devicePath = strings.TrimPrefix(devicePath, "/")
	if i := strings.IndexByte(devicePath, '/'); i >= 0 {
		return devicePath[:i], devicePath[i+1:]
	}
	return devicePath, ""
}

// findZFSVdev scans the attached block devices looking for the
// FIRST device whose vdev label names `pool`. Used for single-
// vdev and mirror pools where one leg is sufficient.
func findZFSVdev(pool string) (string, error) {
	legs, err := findZFSVdevs(pool)
	if err != nil {
		return "", err
	}
	return legs[0], nil
}

// findZFSVdevs returns ALL devices belonging to `pool` in the
// vdev-id order required by fszfs.OpenFromDevices. For single-vdev
// pools the slice has one entry. For mirror, any leg works but we
// return the leg-0 entry first. For raidz the slice is in the
// canonical id order so OpenFromDevices builds the right raidz
// geometry.
//
// The leaf devices are discovered via fszfs.ProbeLabel which fully
// decodes the vdev label NVList. Group by PoolName + PoolGUID;
// within a pool sort by matching each leg's `ThisGUID` against the
// top vdev's `LeafGUIDs` ordering.
func findZFSVdevs(pool string) ([]string, error) {
	devices, err := listWholeDisks()
	if err != nil {
		return nil, err
	}
	type candidate struct {
		path string
		info *fszfs.LabelInfo
	}
	var hits []candidate
	for _, dev := range devices {
		f, err := os.Open(dev)
		if err != nil {
			continue
		}
		info, err := fszfs.ProbeLabel(f, 0)
		f.Close()
		if err != nil {
			continue
		}
		if info.PoolName == pool {
			hits = append(hits, candidate{dev, info})
		}
	}
	if len(hits) == 0 {
		return nil, fmt.Errorf("no attached block device carries a ZFS vdev label naming pool %q", pool)
	}
	// Single-vdev pool: one leg.
	first := hits[0].info
	if len(first.LeafGUIDs) == 0 {
		return []string{hits[0].path}, nil
	}
	// Multi-vdev pool: sort hits by their position in the top vdev's
	// LeafGUIDs slice. Each leg's ThisGUID identifies its slot.
	leafIdx := make(map[uint64]int, len(first.LeafGUIDs))
	for i, g := range first.LeafGUIDs {
		leafIdx[g] = i
	}
	out := make([]string, len(first.LeafGUIDs))
	matched := 0
	for _, h := range hits {
		// Skip legs that don't belong to this pool (we already
		// filtered by PoolName, but PoolGUID is the authoritative
		// match for ambiguous renames).
		if h.info.PoolGUID != first.PoolGUID {
			continue
		}
		idx, ok := leafIdx[h.info.ThisGUID]
		if !ok {
			continue
		}
		if out[idx] != "" {
			return nil, fmt.Errorf("zfs: pool %q: duplicate leg at id %d (%s and %s)", pool, idx, out[idx], h.path)
		}
		out[idx] = h.path
		matched++
	}
	if matched != len(out) {
		missing := []int{}
		for i, p := range out {
			if p == "" {
				missing = append(missing, i)
			}
		}
		return nil, fmt.Errorf("zfs: pool %q: missing %d leg(s) (indices %v); have %d, need %d",
			pool, len(missing), missing, matched, len(out))
	}
	return out, nil
}

func indexOf(haystack, needle []byte) int {
	return indexOfFrom(haystack, needle, 0)
}
func indexOfFrom(haystack, needle []byte, start int) int {
	if len(needle) == 0 {
		return start
	}
	for i := start; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
