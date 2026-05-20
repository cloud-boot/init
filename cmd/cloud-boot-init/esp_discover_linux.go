//go:build linux

// EFI System Partition discovery from a freshly-booted Linux PID 1.
//
// The menu-then-reboot sink needs to write the chosen target's
// vmlinuz + initrd onto the ESP so the firmware can boot them on
// the next round via `Boot0001`. To do that we have to find which
// block device IS the ESP, then mount it read-write.
//
// Strategy:
//
//  1. Walk every entry in /proc/partitions. For each block device,
//     read its first 4 KiB and look for the GPT signature + the
//     partition entry array. The ESP is the partition whose Type
//     GUID is `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`. (The same
//     GPT-walking code as disk_resolve_linux.go's findGPT, but
//     filtered by a known type GUID instead of by PARTLABEL.)
//
//  2. Once located, mount the partition at /esp via
//     `unix.Mount(devPath, "/esp", "vfat", 0, "")`. The bootstrap
//     kernel needs CONFIG_VFAT_FS=y for that — disk-arm64.config
//     gains the right options in the same commit that introduces
//     this file.
//
//  3. Return the mountpoint string. Caller writes files under it
//     and unmounts in defer.
//
// The location of the ESP isn't fixed (Apple VZ + most cloud
// images put it at partition 14 / 15, Alpine puts it at partition
// 0, …) so we always probe rather than assume.

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

const espMountPoint = "/esp"

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
// reads its GPT, and returns the partition path matching
// espTypeGUID. Re-uses disk_resolve_linux.go's listWholeDisks /
// readGPTEntries / partitionPathFor helpers so we don't fork the
// GPT parser.
func findESPDevice() (string, error) {
	disks, err := listWholeDisks()
	if err != nil {
		return "", fmt.Errorf("list whole disks: %w", err)
	}
	for _, d := range disks {
		entries, err := readGPTEntries(d)
		if err != nil || entries == nil {
			continue
		}
		for _, e := range entries {
			if bytes.Equal(e.TypeGUID[:], espTypeGUID[:]) {
				p, err := partitionPathFor(d, &e)
				if err != nil {
					continue
				}
				log.Printf("esp: found at %s (firstLBA=%d lastLBA=%d)",
					p, e.FirstLBA, e.LastLBA)
				return p, nil
			}
		}
	}
	return "", errors.New("no EFI System Partition found on any GPT disk")
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
