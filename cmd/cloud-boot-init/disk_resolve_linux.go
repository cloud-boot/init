//go:build linux

// Disk-device resolver: maps a `device =` spec like "LABEL=foo" or
// "PARTUUID=12345..." to a concrete /dev/<name> path, by reading the
// relevant on-disk metadata directly.
//
// Same syntax as the Linux kernel's `root=` cmdline arg:
//
//	/dev/vda1            literal path → passes through unchanged
//	LABEL=foo            fs label across ext{2,3,4} / xfs / btrfs
//	UUID=8400-…          fs UUID  across ext{2,3,4} / xfs / btrfs
//	PARTLABEL=foo        GPT partition name (UTF-16LE, 36 chars max)
//	PARTUUID=8400-…      GPT partition unique GUID
//
// LABEL/UUID try each filesystem-specific superblock layout in turn:
//
//	ext{2,3,4}  offset 1024, magic 0xEF53 at sb+56, uuid at sb+104, label at sb+120
//	xfs         offset 0,    magic "XFSB"  at sb+0,  uuid at sb+32,  label at sb+108
//	btrfs       offset 65536,magic "_BHRfS_M" at sb+64,uuid at sb+32,label at sb+299
//
// PARTLABEL/PARTUUID enumerate the GPT entry array on every whole-disk
// block device — fs-agnostic. We deliberately don't shell out to blkid;
// cloud-boot's initramfs ships without util-linux.

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf16"
)

// resolveBlockDevice turns a `device =` spec into an absolute path.
// Returns the spec untouched if it already looks like a /dev path.
func resolveBlockDevice(spec string) (string, error) {
	if spec == "" {
		return "", errors.New("empty device spec")
	}
	if strings.HasPrefix(spec, "/") {
		return spec, nil
	}
	if v, ok := strings.CutPrefix(spec, "LABEL="); ok {
		return findFS(func(s *fsLabel) bool { return s.label == v })
	}
	if v, ok := strings.CutPrefix(spec, "UUID="); ok {
		v = strings.ToLower(v)
		return findFS(func(s *fsLabel) bool { return strings.ToLower(s.uuid) == v })
	}
	if v, ok := strings.CutPrefix(spec, "PARTLABEL="); ok {
		return findGPT(func(e *gptEntry) bool { return e.name() == v })
	}
	if v, ok := strings.CutPrefix(spec, "PARTUUID="); ok {
		v = strings.ToLower(v)
		return findGPT(func(e *gptEntry) bool { return strings.ToLower(e.uuid()) == v })
	}
	return "", fmt.Errorf("unsupported device spec %q (want /dev/…, LABEL=…, UUID=…, PARTLABEL=…, or PARTUUID=…)", spec)
}

// ─── fs-agnostic LABEL / UUID lookup ──────────────────────────────────
//
// findFS scans every entry in /proc/partitions, calls readFSLabel
// (cross-platform, lives in disk_resolve.go) which probes ext{2,3,4} /
// xfs / btrfs in turn, and returns the first device whose normalised
// {label, uuid} matches.

func findFS(match func(*fsLabel) bool) (string, error) {
	parts, err := listBlockDevs()
	if err != nil {
		return "", err
	}
	// Diagnostic trail — when no match is found the error tells the
	// user something actionable ("the kernel sees X, Y, Z; X has no
	// recognisable superblock; Y is xfs with label='foo'") instead of
	// a bare "not found" on a serial console.
	var seen []string
	for _, p := range parts {
		s, err := readFSLabel(p)
		if err != nil {
			seen = append(seen, fmt.Sprintf("%s=<open-err:%v>", p, err))
			continue
		}
		if s == nil {
			seen = append(seen, fmt.Sprintf("%s=<unknown-fs>", p))
			continue
		}
		seen = append(seen, fmt.Sprintf("%s=%s{label=%q uuid=%s}", p, s.fsType, s.label, s.uuid))
		if match(s) {
			return p, nil
		}
	}
	return "", fmt.Errorf("no block device matches; scanned %d entries: %s", len(seen), strings.Join(seen, ", "))
}

// ─── GPT (PARTLABEL / PARTUUID) ───────────────────────────────────────

const (
	gptHeaderLBA   = 1
	gptSectorSize  = 512
	gptSigASCII    = "EFI PART"
	gptEntrySizeMin = 128 // entries are usually exactly 128 bytes
)

type gptEntry struct {
	TypeGUID   [16]byte
	UniqueGUID [16]byte
	FirstLBA   uint64
	LastLBA    uint64
	Attrs      uint64
	NameUTF16  [72]byte
}

func (e *gptEntry) name() string {
	u16 := make([]uint16, 0, 36)
	for i := 0; i+1 < len(e.NameUTF16); i += 2 {
		c := uint16(e.NameUTF16[i]) | uint16(e.NameUTF16[i+1])<<8
		if c == 0 {
			break
		}
		u16 = append(u16, c)
	}
	return string(utf16.Decode(u16))
}

func (e *gptEntry) uuid() string {
	return guidString(e.UniqueGUID[:])
}

// guidString formats a 16-byte GPT GUID into RFC-4122 textual form.
// The first three groups are little-endian inside the GUID blob, the
// last two are big-endian — same convention as PARTUUID elsewhere.
func guidString(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[3], b[2], b[1], b[0],
		b[5], b[4],
		b[7], b[6],
		b[8], b[9],
		b[10], b[11], b[12], b[13], b[14], b[15])
}

// readGPTEntries reads the partition entries array off a whole-disk
// block device. Returns (nil, nil) when the GPT signature is absent
// (e.g. an MBR-only disk or one without partitioning), so the caller
// can keep scanning. CRC validation is intentionally skipped — the
// Linux kernel itself accepts entries arrays without recomputed CRC,
// and our use case (label lookup) is reasonably tolerant of partial
// corruption.
func readGPTEntries(path string) ([]gptEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var hdr [gptSectorSize]byte
	if _, err := f.Seek(gptHeaderLBA*gptSectorSize, io.SeekStart); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return nil, err
	}
	if string(hdr[0:8]) != gptSigASCII {
		return nil, nil
	}
	entriesLBA := binary.LittleEndian.Uint64(hdr[72:80])
	numEntries := binary.LittleEndian.Uint32(hdr[80:84])
	entrySize := binary.LittleEndian.Uint32(hdr[84:88])
	if entrySize < gptEntrySizeMin || numEntries == 0 || numEntries > 1024 {
		return nil, fmt.Errorf("GPT entry array looks bogus (num=%d size=%d)", numEntries, entrySize)
	}
	if _, err := f.Seek(int64(entriesLBA)*gptSectorSize, io.SeekStart); err != nil {
		return nil, err
	}
	out := make([]gptEntry, 0, numEntries)
	raw := make([]byte, entrySize)
	for i := uint32(0); i < numEntries; i++ {
		if _, err := io.ReadFull(f, raw); err != nil {
			return nil, err
		}
		// Skip empty entries (type GUID all zeros).
		if isZero(raw[:16]) {
			continue
		}
		var e gptEntry
		copy(e.TypeGUID[:], raw[0:16])
		copy(e.UniqueGUID[:], raw[16:32])
		e.FirstLBA = binary.LittleEndian.Uint64(raw[32:40])
		e.LastLBA = binary.LittleEndian.Uint64(raw[40:48])
		e.Attrs = binary.LittleEndian.Uint64(raw[48:56])
		copy(e.NameUTF16[:], raw[56:128])
		out = append(out, e)
	}
	return out, nil
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// findGPT enumerates whole-disk block devices (everything in
// /proc/partitions whose name has no trailing digit, modulo nvme's
// `pN` suffix), reads the GPT, and returns the path of the partition
// whose entry satisfies match. The returned path uses Linux's
// per-driver suffix convention: `vda1`, `sda1`, `nvme0n1p1`, etc.
func findGPT(match func(*gptEntry) bool) (string, error) {
	disks, err := listWholeDisks()
	if err != nil {
		return "", err
	}
	for _, d := range disks {
		entries, err := readGPTEntries(d)
		if err != nil || entries == nil {
			continue
		}
		// `entries` skips empty slots, so we have to track the
		// original index to build the partition path. We rebuild it
		// from FirstLBA by re-reading sequentially.
		// Simpler: iterate /proc/partitions for partitions sharing
		// this disk's prefix, sorted by sysfs `partition` number.
		for _, e := range entries {
			if !match(&e) {
				continue
			}
			return partitionPathFor(d, &e)
		}
	}
	return "", errors.New("no block device matches the requested PARTLABEL/PARTUUID")
}

// listWholeDisks returns /dev/<name> paths for whole-disk block
// devices known to the kernel (i.e. entries that aren't a partition
// of another entry).
func listWholeDisks() ([]string, error) {
	all, err := listBlockDevs()
	if err != nil {
		return nil, err
	}
	// A device is a "partition" iff there's a sibling device that's a
	// strict prefix and the suffix is digits-only (or `pN` for nvme).
	isPart := make(map[string]bool, len(all))
	for _, p := range all {
		name := strings.TrimPrefix(p, "/dev/")
		// Heuristic: try peeling trailing digits, and the `p<n>` form
		// for nvme.
		for parent := range parentCandidates(name) {
			parentPath := "/dev/" + parent
			for _, q := range all {
				if q == parentPath {
					isPart[p] = true
				}
			}
		}
	}
	var out []string
	for _, p := range all {
		if !isPart[p] {
			out = append(out, p)
		}
	}
	return out, nil
}

// parentCandidates yields whole-disk names that could be the parent
// of a given partition name. Covers vdaN → vda, sdaN → sda,
// nvme0n1pN → nvme0n1. Returns an empty map for non-partition names.
func parentCandidates(name string) map[string]struct{} {
	out := map[string]struct{}{}
	// Trailing digits → strip them: vda1 → vda
	for i := len(name); i > 0; i-- {
		if name[i-1] < '0' || name[i-1] > '9' {
			if i < len(name) {
				out[name[:i]] = struct{}{}
			}
			break
		}
	}
	// nvme0n1p1 → nvme0n1 (strip `pN` suffix)
	if idx := strings.LastIndex(name, "p"); idx > 0 {
		tail := name[idx+1:]
		allDigits := tail != ""
		for _, c := range tail {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			out[name[:idx]] = struct{}{}
		}
	}
	return out
}

// partitionPathFor maps (disk, entry) back to a partition path. We
// re-list `disk`'s GPT entries in raw order so we know the slot
// number of `entry`, then assemble the kernel-style partition name.
func partitionPathFor(disk string, entry *gptEntry) (string, error) {
	f, err := os.Open(disk)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var hdr [gptSectorSize]byte
	if _, err := f.Seek(gptHeaderLBA*gptSectorSize, io.SeekStart); err != nil {
		return "", err
	}
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return "", err
	}
	entriesLBA := binary.LittleEndian.Uint64(hdr[72:80])
	numEntries := binary.LittleEndian.Uint32(hdr[80:84])
	entrySize := binary.LittleEndian.Uint32(hdr[84:88])
	if _, err := f.Seek(int64(entriesLBA)*gptSectorSize, io.SeekStart); err != nil {
		return "", err
	}
	raw := make([]byte, entrySize)
	for slot := uint32(1); slot <= numEntries; slot++ {
		if _, err := io.ReadFull(f, raw); err != nil {
			return "", err
		}
		if isZero(raw[:16]) {
			continue
		}
		if bytes.Equal(raw[16:32], entry.UniqueGUID[:]) {
			return assemblePartitionPath(disk, slot), nil
		}
	}
	return "", fmt.Errorf("partition matched but slot lookup failed on %s", disk)
}

// assemblePartitionPath glues a disk path and a 1-based slot index
// using the kernel's naming convention for that driver.
func assemblePartitionPath(disk string, slot uint32) string {
	name := strings.TrimPrefix(disk, "/dev/")
	// nvme0n1 → nvme0n1p1; everything else → vda1 / sda1 / xvda1.
	if strings.HasPrefix(name, "nvme") || strings.HasPrefix(name, "mmcblk") || strings.HasPrefix(name, "loop") {
		return fmt.Sprintf("/dev/%sp%d", name, slot)
	}
	return fmt.Sprintf("/dev/%s%d", name, slot)
}

// ─── shared: /proc/partitions reader ──────────────────────────────────

// listBlockDevs returns /dev/<name> paths for every entry in
// /proc/partitions (whole disks and partitions alike). Sorted as
// /proc/partitions reports them, which is the kernel's enumeration
// order — fine for our scan.
func listBlockDevs() ([]string, error) {
	f, err := os.Open("/proc/partitions")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[0] == "major" {
			continue
		}
		out = append(out, "/dev/"+fields[3])
	}
	return out, sc.Err()
}
