//go:build linux

// UEFI LoadOption encoding + efivarfs writes for the menu-then-reboot
// sink (commit 4/5 of the series — see memory:uki-menu-then-reboot).
//
// The sink stages kernel + initrd under \EFI\Linux\ on the FAT ESP
// (commit 3) and then needs to point the firmware at the staged
// vmlinuz on the next boot. UEFI's mechanism for that is the
// Boot#### variable in EFI_GLOBAL_VARIABLE space plus the BootOrder
// variable that orders them.
//
// This file:
//
//  1. encodeLoadOption(description, filePath, cmdline)
//     Builds an EFI_LOAD_OPTION per UEFI 2.10 §3.1.3 — a packed
//     byte sequence:
//
//        UINT32   Attributes        (LOAD_OPTION_ACTIVE = 0x01)
//        UINT16   FilePathListLength
//        CHAR16   Description[]     UTF-16LE, NUL-terminated
//        Device-path nodes …        (FILE_PATH + END)
//        UINT8    OptionalData[]    UTF-16LE cmdline
//
//     For FilePathList we use the "short-form" path: just a single
//     FILE_PATH node with the backslash-prefixed UEFI path string,
//     followed by the END node (type=0x7F, subtype=0xFF, length=4).
//     UEFI 2.10 §3.1.2 says the boot manager treats short-form as
//     "look on every connected SimpleFileSystem" — vfkit / Apple VZ
//     + EDK2 both accept it.
//
//  2. writeBoot0001(loadOption)
//     Writes the encoded payload to /sys/firmware/efi/efivars/
//     Boot0001-8BE4DF61-93CA-11D2-AA0D-00E098032B8C with the
//     4-byte attributes header efivarfs prepends to every
//     variable's data (NV|BS|RT = 0x07). Atomic — single write
//     of (header || payload).
//
//  3. prependToBootOrder(0x0001)
//     Reads the current BootOrder array (UINT16 LE list), inserts
//     0001 at position 0 unless it's already there, writes the
//     full list back. Same efivarfs path + 4-byte header.
//
// efivarfs is mounted at /sys/firmware/efi/efivars by the kernel
// when CONFIG_EFIVAR_FS=y (added to disk-arm64.config in commit 2).
// On a fresh boot it's not automounted — we mount it ourselves at
// the start of writeBoot0001 if absent.

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const (
	// EFI_GLOBAL_VARIABLE GUID in the standard textual form used
	// by efivarfs filenames.
	efiGlobalGUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

	// Attribute bits for a Boot#### variable.
	efiAttrNonVolatile      uint32 = 0x00000001
	efiAttrBootServAccess   uint32 = 0x00000002
	efiAttrRuntimeAccess    uint32 = 0x00000004
	efiAttrsNVBSRT          uint32 = efiAttrNonVolatile | efiAttrBootServAccess | efiAttrRuntimeAccess

	// LoadOption.Attributes bits.
	loadOptionActive uint32 = 0x00000001

	// efivarfs mount point.
	efivarsDir = "/sys/firmware/efi/efivars"
)

// ensureEfivarfs mounts efivarfs at /sys/firmware/efi/efivars if it
// isn't already there. The bootstrap kernel ships with
// CONFIG_EFIVAR_FS=y but doesn't auto-mount in early initramfs.
func ensureEfivarfs() error {
	// Cheap "already mounted?" check: stat the well-known
	// "<guid>-<guid>" sentinel file. efivarfs always exposes
	// at least one var.
	if _, err := os.Stat(efivarsDir + "/SecureBoot-" + efiGlobalGUID); err == nil {
		return nil
	}
	// Fall back to stat'ing the dir itself; if it has any entry
	// we assume it's already mounted.
	entries, _ := os.ReadDir(efivarsDir)
	if len(entries) > 0 {
		return nil
	}
	if err := os.MkdirAll(efivarsDir, 0o755); err != nil {
		return err
	}
	if err := unix.Mount("efivarfs", efivarsDir, "efivarfs", 0, ""); err != nil {
		return fmt.Errorf("mount efivarfs: %w", err)
	}
	log.Printf("mounted efivarfs at %s", efivarsDir)
	return nil
}

// utf16leZ appends s as UTF-16LE followed by a 2-byte NUL.
func utf16leZ(out []byte, s string) []byte {
	for _, r := range s {
		// Encode BMP code points only — ASCII is the common case,
		// non-BMP surrogate pairs would need extra logic but the
		// description + cmdline + path strings we deal with are
		// always ASCII.
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], uint16(r))
		out = append(out, b[:]...)
	}
	out = append(out, 0, 0)
	return out
}

// encodeFilePathNode builds a single MEDIA_FILEPATH (type=0x04,
// subtype=0x04) device-path node carrying `path` as UTF-16LE +
// NUL terminator. Header = 4 bytes, body = 2*len(path)+2.
func encodeFilePathNode(path string) []byte {
	body := utf16leZ(nil, path)
	nodeLen := 4 + len(body)
	node := make([]byte, 4, nodeLen)
	node[0] = 0x04 // MEDIA_DEVICE_PATH
	node[1] = 0x04 // FILEPATH
	binary.LittleEndian.PutUint16(node[2:4], uint16(nodeLen))
	node = append(node, body...)
	return node
}

// endDevicePathNode — the obligatory terminator for any
// EFI_DEVICE_PATH_PROTOCOL list. Type=0x7F, SubType=0xFF, Length=4.
var endDevicePathNode = []byte{0x7F, 0xFF, 0x04, 0x00}

// encodeLoadOption builds an EFI_LOAD_OPTION suitable for writing
// as Boot0001 / Boot####.
//
//	description:  human-readable name; rendered in firmware UI
//	filePath:     ESP-rooted UEFI path, backslash-prefixed,
//	              e.g. `\EFI\Linux\debian-cloud-vmlinuz.efi`
//	cmdline:      OptionalData payload — usually
//	              `initrd=\EFI\Linux\<t>-initrd <plan.cmdline>`
//	              for an EFI-stub kernel.
//
// The cmdline lands in OptionalData as UTF-16LE NUL-terminated,
// because that's what the Linux EFI stub expects (it parses
// LoadedImage.LoadOptions as a wide string).
func encodeLoadOption(description, filePath, cmdline string) []byte {
	fp := encodeFilePathNode(filePath)
	fpList := append(fp, endDevicePathNode...)

	out := make([]byte, 6)
	binary.LittleEndian.PutUint32(out[0:4], loadOptionActive)
	binary.LittleEndian.PutUint16(out[4:6], uint16(len(fpList)))
	out = utf16leZ(out, description)
	out = append(out, fpList...)
	if cmdline != "" {
		out = utf16leZ(out, cmdline)
	}
	return out
}

// writeEFIVar writes `data` to /sys/firmware/efi/efivars/<name>-<guid>
// prefixed with the 4-byte attributes header efivarfs requires.
// `attrs` is typically efiAttrsNVBSRT (=0x07) for boot variables.
//
// efivarfs requires the write to be a single syscall — partial
// writes fail with EIO. We open with O_WRONLY|O_CREAT, write the
// whole header+payload in one go, then close.
//
// Existing variables can't be overwritten with a regular open;
// efivarfs flips the file's immutable bit on every create. We
// clear it via FS_IOC_SETFLAGS before writing, then let efivarfs
// re-set it on close.
func writeEFIVar(name string, attrs uint32, data []byte) error {
	if err := ensureEfivarfs(); err != nil {
		return err
	}
	path := filepath.Join(efivarsDir, name+"-"+efiGlobalGUID)
	// Clear immutable if the var already exists.
	if _, err := os.Stat(path); err == nil {
		if err := setImmutable(path, false); err != nil {
			log.Printf("warn: clear immutable on %s: %v", path, err)
		}
	}
	buf := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint32(buf[0:4], attrs)
	copy(buf[4:], data)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	n, err := f.Write(buf)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if n != len(buf) {
		return fmt.Errorf("short write %s: %d/%d", path, n, len(buf))
	}
	return nil
}

// readEFIVar pulls back the data portion of /sys/firmware/efi/
// efivars/<name>-<guid>, stripping the 4-byte attributes header.
// Returns (nil, nil) if the variable doesn't exist — non-fatal,
// the caller treats it as "no current BootOrder, start a new one".
func readEFIVar(name string) ([]byte, error) {
	path := filepath.Join(efivarsDir, name+"-"+efiGlobalGUID)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("var %s: short read (%d bytes)", path, len(data))
	}
	return data[4:], nil
}

// setImmutable toggles FS_IMMUTABLE_FL on `path`. efivarfs sets
// it on creation so casual `cat > file` doesn't work; we have to
// clear it before re-writing an existing variable.
func setImmutable(path string, on bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var flags uint32
	// FS_IOC_GETFLAGS / FS_IOC_SETFLAGS are arch-specific ioctls;
	// unix.IoctlGetInt + IoctlSetPointerInt cover the common case.
	r, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return err
	}
	flags = uint32(r)
	const fsImmutable = 0x00000010 // FS_IMMUTABLE_FL
	if on {
		flags |= fsImmutable
	} else {
		flags &^= fsImmutable
	}
	return unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, int(flags))
}

// prependToBootOrder reads the current BootOrder (a sequence of
// little-endian UINT16s) and inserts `entry` at position 0 unless
// it's already at the front. The full updated list is written
// back. Missing-variable is treated as "current BootOrder is
// empty" — we install [entry] from scratch.
func prependToBootOrder(entry uint16) error {
	cur, err := readEFIVar("BootOrder")
	if err != nil {
		return err
	}
	// Decode current entries.
	var entries []uint16
	for i := 0; i+1 < len(cur); i += 2 {
		entries = append(entries, binary.LittleEndian.Uint16(cur[i:i+2]))
	}
	// Already first? No-op.
	if len(entries) > 0 && entries[0] == entry {
		return nil
	}
	// Drop any pre-existing copy further down, then prepend.
	out := make([]uint16, 0, len(entries)+1)
	out = append(out, entry)
	for _, e := range entries {
		if e == entry {
			continue
		}
		out = append(out, e)
	}
	buf := make([]byte, 2*len(out))
	for i, e := range out {
		binary.LittleEndian.PutUint16(buf[i*2:i*2+2], e)
	}
	return writeEFIVar("BootOrder", efiAttrsNVBSRT, buf)
}
