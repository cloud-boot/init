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

	fszfs "github.com/go-filesystems/zfs"
)

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

	devPath, err := findZFSVdev(pool)
	if err != nil {
		return fmt.Errorf("zfs target %q: locating vdev for pool %q: %w", p.Device, pool, err)
	}
	log.Printf("zfs: pool %q found on %s; opening dataset %q", pool, devPath, datasetPath)

	fs, err := fszfs.OpenDataset(devPath, -1, datasetPath)
	if err != nil {
		return fmt.Errorf("zfs open %s (dataset %q): %w", devPath, datasetPath, err)
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

// findZFSVdev scans the attached block devices (virtio-blk
// children of the running VM) looking for a ZFS vdev label
// whose pool-name nvpair matches `pool`. The library doesn't
// expose label parsing yet, so we use a lightweight string-
// match heuristic: read a small window at offset 16 KiB
// (where the first vdev label's NVList starts on a 256 KiB
// label) and look for "name=<pool>" in the XDR'd text.
//
// This is good enough for the typical single-vdev case (the
// pool name appears in plain ASCII inside the XDR-encoded
// nvlist). Multi-vdev pools would need a proper NVList
// reader — see memory:zfs-root-support for the roadmap.
func findZFSVdev(pool string) (string, error) {
	devices, err := listWholeDisks()
	if err != nil {
		return "", err
	}
	needle := []byte(pool)
	for _, dev := range devices {
		f, err := os.Open(dev)
		if err != nil {
			continue
		}
		buf := make([]byte, 32*1024) // first label's NVList region
		_, err = f.ReadAt(buf, 16*1024)
		f.Close()
		if err != nil {
			continue
		}
		// The pool name shows up as raw ASCII inside the XDR
		// nvpair payload (variable-length string after the
		// 4-byte length prefix). Looking for the literal name
		// near a "name" key minimises false positives.
		if idx := indexOf(buf, []byte("name")); idx >= 0 && indexOfFrom(buf, needle, idx) > idx {
			return dev, nil
		}
	}
	return "", fmt.Errorf("no attached block device carries a ZFS vdev label naming pool %q", pool)
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
