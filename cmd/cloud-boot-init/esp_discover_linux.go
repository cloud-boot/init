//go:build linux

// EFI System Partition discovery from a freshly-booted Linux PID 1.
//
// The menu-then-reboot sink needs to write the chosen target's
// vmlinuz + initrd onto an ESP so the firmware can boot them on
// the next round via `Boot0001`. The right ESP is the one on the
// dedicated **cloud-boot cache disk** — a small writable virtio-
// blk attached alongside the (now read-only) boot.iso. It's
// identified by GPT partition name "cloud-boot-cache", which the
// host-side `uki/scripts/make-cache-disk.sh` stamps at creation
// time.
//
// Why name-match, not just type-match: under a typical menu-then-
// reboot run the VM has at least one other ESP visible — most
// cloud-image DISK targets (Debian, Ubuntu, Fedora, …) carry their
// own EFI System Partition for their own bootloader. Writing
// \EFI\Linux\<T>-vmlinuz.efi into one of those would land outside
// the cache disk, polluting the distro image and possibly trapping
// the firmware on the wrong partition after reboot. The name match
// keeps the mutation surface to a single well-known disk.
//
// Strategy:
//
//  1. Walk every whole-disk entry in /proc/partitions and read its
//     GPT (re-using disk_resolve_linux.go's parser).
//  2. Collect every GPT entry whose TypeGUID is the ESP GUID
//     (C12A7328-F81F-11D2-BA4B-00A0C93EC93B).
//  3. Prefer the one whose GPT name is "cloud-boot-cache". If
//     absent: warn and pick the first ESP (back-compat for ad-hoc
//     test setups). If multiple ESPs are present and none match,
//     fail clearly — the operator forgot to create the cache disk.
//  4. Mount it at /esp via `unix.Mount(devPath, "/esp", "vfat",
//     0, "")`. The kernel needs CONFIG_VFAT_FS=y (cloud variant
//     ships it).
//  5. Return the mountpoint string. Caller writes files under it
//     and unmounts in defer.

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/sys/unix"
)

const (
	espMountPoint = "/esp"

	// cachePartitionName is the GPT partition name set by
	// uki/scripts/make-cache-disk.sh on the cloud-boot cache
	// disk's ESP. findESPDevice prefers it over any other ESP
	// (e.g. one belonging to an attached cloud-image DISK
	// target) so the reboot sink stages targets onto the
	// dedicated writable disk, not somebody else's bootloader
	// partition.
	cachePartitionName = "cloud-boot-cache"
)

// espTypeGUID — EFI System Partition GPT type GUID, in raw on-disk
// (mixed-endian) byte order.
//
// Canonical text form: C12A7328-F81F-11D2-BA4B-00A0C93EC93B.
//
// In the GPT entry the first three groups are little-endian, the
// last two are big-endian — same mixed-endian convention PARTUUID
// elsewhere uses.
var espTypeGUID = [16]byte{
	0x28, 0x73, 0x2A, 0xC1,
	0x1F, 0xF8,
	0xD2, 0x11,
	0xBA, 0x4B,
	0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
}

// findAndMountESP walks block devices, identifies the FAT EFI
// System Partition by GPT type GUID, and mounts it at /esp.
// Returns the mountpoint on success.
func findAndMountESP() (string, error) {
	dev, err := findESPDevice()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(espMountPoint, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", espMountPoint, err)
	}
	log.Printf("esp: mounting %s on %s (vfat, rw)", dev, espMountPoint)
	// No iocharset= argument: the kernel falls back to
	// CONFIG_NLS_DEFAULT (iso8859-1 on cloud-arm64.config,
	// ascii on disk-arm64.config). Hardcoding `iocharset=ascii`
	// makes the mount fail with EINVAL on any kernel that lacks
	// CONFIG_NLS_ASCII=y. The \EFI\Linux\<target>-* filenames
	// the reboot sink writes are pure ASCII anyway — iso8859-1
	// and ascii are indistinguishable in that subset.
	if err := unix.Mount(dev, espMountPoint, "vfat", 0, ""); err != nil {
		return "", fmt.Errorf("mount %s as vfat: %w", dev, err)
	}
	return espMountPoint, nil
}

// findESPDevice scans every /proc/partitions whole-disk entry,
// reads its GPT, and returns the partition path of the cloud-
// boot cache disk's ESP. Strategy: prefer a GPT entry whose
// partition name is `cachePartitionName`; if none matches but
// exactly one ESP exists overall, pick it (back-compat with
// test setups that don't yet stamp the name); if multiple
// nameless ESPs are present, fail with a clear hint about
// running `uki/scripts/make-cache-disk.sh`.
func findESPDevice() (string, error) {
	disks, err := listWholeDisks()
	if err != nil {
		return "", fmt.Errorf("list whole disks: %w", err)
	}

	type candidate struct {
		path     string
		first    uint64
		last     uint64
		gptName  string
	}
	var all []candidate
	for _, d := range disks {
		entries, err := readGPTEntries(d)
		if err != nil || entries == nil {
			continue
		}
		for i := range entries {
			e := &entries[i]
			if !bytes.Equal(e.TypeGUID[:], espTypeGUID[:]) {
				continue
			}
			p, err := partitionPathFor(d, e)
			if err != nil {
				continue
			}
			all = append(all, candidate{
				path:    p,
				first:   e.FirstLBA,
				last:    e.LastLBA,
				gptName: e.name(),
			})
		}
	}
	if len(all) == 0 {
		return "", errors.New("no EFI System Partition found on any GPT disk (did you forget to attach the cloud-boot cache disk?)")
	}
	for _, c := range all {
		if c.gptName == cachePartitionName {
			log.Printf("esp: cache disk found at %s (firstLBA=%d lastLBA=%d name=%q)",
				c.path, c.first, c.last, c.gptName)
			return c.path, nil
		}
	}
	if len(all) == 1 {
		c := all[0]
		log.Printf("esp: WARN no partition named %q; falling back to the only ESP %s (firstLBA=%d lastLBA=%d name=%q)",
			cachePartitionName, c.path, c.first, c.last, c.gptName)
		return c.path, nil
	}
	names := make([]string, 0, len(all))
	for _, c := range all {
		names = append(names, fmt.Sprintf("%s(name=%q)", c.path, c.gptName))
	}
	return "", fmt.Errorf("multiple ESPs and none named %q — attach the cloud-boot cache disk (host: uki/scripts/make-cache-disk.sh). Candidates: %v",
		cachePartitionName, names)
}

// Tiny sanity helper used by tests + the reboot sink: read the
// first sector of `dev` and check for the FAT BS_OEMName / valid
// boot-sector signature, so we can distinguish a freshly-formatted
// FAT volume from a corrupted GPT entry that claims ESP type.
//
// Used opportunistically — if it fails we still try to mount.
func looksLikeFAT(dev string) bool {
	f, err := os.Open(dev)
	if err != nil {
		return false
	}
	defer f.Close()
	var buf [512]byte
	if _, err := io.ReadFull(f, buf[:]); err != nil {
		return false
	}
	// BPB_BytsPerSec at offset 11 — must be one of 512/1024/2048/4096.
	bps := binary.LittleEndian.Uint16(buf[11:13])
	switch bps {
	case 512, 1024, 2048, 4096:
	default:
		return false
	}
	// Trailing signature 0x55 0xAA.
	return buf[510] == 0x55 && buf[511] == 0xAA
}
