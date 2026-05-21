//go:build linux

// LUKS detection for the disk-target path.
//
// cloud-boot-init reads /boot/vmlinuz + /boot/initrd from a chained
// distro's filesystem to stage them for kexec. When /boot is on an
// UNENCRYPTED partition (the common case — Proxmox, Ubuntu Server,
// Debian, Fedora all keep /boot in plain ext4 or vfat by default,
// even with LUKS-encrypted /), the existing ext4/xfs/btrfs path
// just works.
//
// When /boot lives INSIDE a LUKS-encrypted partition (full-disk
// encryption with GRUB 2.04+ LUKS-readable /boot), we'd need to:
//   1. detect LUKS via go-fde/luks.Detect(devPath)
//   2. unlock with a passphrase (cloudboot.disk.luks-passphrase=
//      cmdline knob, or fetched via metadata.url)
//   3. layer the resulting *luks.Device under the FS opener
//
// Step 3 requires the FS opener to accept an io.ReaderAt rather
// than a path. Today only github.com/go-filesystems/ext4 has an
// OpenFromDevice (with unexported blockDevice interface); xfs /
// btrfs / zfs accept paths only.
//
// What this file delivers TODAY:
//   - detectLUKS(devPath) → bool: lightweight magic-byte check
//     against the LUKS1 / LUKS2 header.
//   - clear error from runDisk when LUKS is seen, telling the
//     operator "your disk is LUKS-encrypted; cloud-boot can't
//     read it yet — wire upstream OpenFromReader first".
//
// What's deferred (memory:userland-fs-drivers tracks the roadmap):
//   - Export blockDevice / add OpenFromReaderAt in each FS lib.
//   - Wire luks.Open + layered FS open in runDisk.
//   - Passphrase plumbing via cmdline / metadata.

package main

import (
	"fmt"
	"os"
)

// LUKS magic strings — found at the very start of the partition.
// LUKS1 uses "LUKS\xba\xbe" (6 bytes), LUKS2 also uses the same
// header magic. We probe the first 16 bytes which is enough to
// distinguish both versions from any non-LUKS payload.
var (
	luks1Magic = []byte{'L', 'U', 'K', 'S', 0xba, 0xbe, 0x00, 0x01}
	luks2Magic = []byte{'L', 'U', 'K', 'S', 0xba, 0xbe, 0x00, 0x02}
)

// detectLUKS opens devPath, reads the first 8 bytes, and returns
// true if it matches a LUKS1 or LUKS2 header magic. Non-fatal: on
// any I/O error we return false (the FS opener will fail later
// with a clearer error than a half-baked LUKS check).
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

// checkNotLUKS is the openFS pre-check that surfaces a friendly
// error when the operator pointed cloud-boot at an encrypted
// volume. Better than letting ext4.Open fail with "bad magic"
// and leave the operator guessing.
func checkNotLUKS(devPath string) error {
	if detectLUKS(devPath) {
		return fmt.Errorf("disk %s is LUKS-encrypted; cloud-boot can't read encrypted volumes yet — point at the unencrypted /boot partition instead, or extend upstream go-filesystems/* with OpenFromReader to layer the LUKS plaintext (see memory:userland-fs-drivers)", devPath)
	}
	return nil
}
