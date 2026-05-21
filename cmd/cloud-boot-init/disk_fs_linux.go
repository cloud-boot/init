//go:build linux

// Pure-Go filesystem dispatch for the disk-target path.
//
// runDisk used to call unix.Mount(2) — which required the bootstrap
// kernel to carry CONFIG_EXT4_FS, CONFIG_XFS_FS, CONFIG_BTRFS_FS as
// in-kernel drivers. ~ everything went through the kernel's VFS.
//
// The userland-driver pivot replaces that mount(2) with a per-FS
// Go reader from github.com/go-filesystems/*: each Open() takes a
// raw block-device path + partition index and returns a
// filesystem.Filesystem the caller can ReadFile / ListDir on
// without any kernel-side mount. Files we need (the chained
// distro's kernel + initrd) are then staged under downloadDir as
// regular files for kexec.Load. Same flow for every fs= value,
// ZFS included — no more "ZFS is special, fall through to mount"
// branch in runDisk.
//
// Net effect on the kernel: disk-arm64.config can drop the in-tree
// CONFIG_EXT4_FS / CONFIG_XFS_FS / CONFIG_BTRFS_FS lines (the
// kernel never mounts those filesystems anymore). Only VFAT
// stays — needed by the reboot sink for the FAT ESP write step,
// where we use unix.Mount because that's a fresh r/w mount we
// own end-to-end.

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	fsbtrfs "github.com/go-filesystems/btrfs"
	fsext4 "github.com/go-filesystems/ext4"
	filesystem "github.com/go-filesystems/interface"
	fsxfs "github.com/go-filesystems/xfs"
)

// stageBootBytes writes the kernel + initrd payloads under
// downloadDir so kexec.Load can mmap them. Returns the staged
// paths.
func stageBootBytes(kBytes, iBytes []byte) (string, string, error) {
	if err := os.MkdirAll(downloadDir, 0o755); err != nil {
		return "", "", err
	}
	kStaged := filepath.Join(downloadDir, "disk-kernel")
	iStaged := filepath.Join(downloadDir, "disk-initrd")
	if err := os.WriteFile(kStaged, kBytes, 0o644); err != nil {
		return "", "", fmt.Errorf("stage kernel: %w", err)
	}
	if err := os.WriteFile(iStaged, iBytes, 0o644); err != nil {
		return "", "", fmt.Errorf("stage initrd: %w", err)
	}
	return kStaged, iStaged, nil
}

// openFS dispatches to the right go-filesystems driver based on
// p.FS. ZFS has its own entry point because its "device" is a
// dataset path rather than a block device — see runDiskZFS for
// the pool-discovery + dataset-traversal dance.
//
// The returned Filesystem is read-only for the boot-time use case
// (cloud-boot only needs to READ /boot/vmlinuz + initrd); writes
// would still work since the underlying drivers are r/w, but we
// don't open the device r/w to avoid surprise mutations.
//
// partIndex=-1 means "whole image" — the lib auto-detects MBR/GPT
// when present and lets us see partition tables. For our case the
// plan target already names the specific partition (resolveBlockDevice
// produces /dev/vdaN, not /dev/vda), so partIndex=-1 just means
// "treat the device path as a bare filesystem image".
func openFS(p diskParams, devicePath string) (filesystem.Filesystem, error) {
	switch p.FS {
	case "", "ext4":
		fs, err := fsext4.Open(devicePath, -1)
		if err != nil {
			return nil, fmt.Errorf("ext4 open %s: %w", devicePath, err)
		}
		return fs, nil
	case "xfs":
		fs, err := fsxfs.Open(devicePath, -1)
		if err != nil {
			return nil, fmt.Errorf("xfs open %s: %w", devicePath, err)
		}
		return fs, nil
	case "btrfs":
		fs, err := fsbtrfs.Open(devicePath, -1)
		if err != nil {
			return nil, fmt.Errorf("btrfs open %s: %w", devicePath, err)
		}
		return fs, nil
	default:
		return nil, fmt.Errorf("openFS: unsupported fs %q (try ext4, xfs, btrfs, zfs)", p.FS)
	}
}

// extractAndStage reads p.Kernel + p.Initrd from `fs` (a Go-driver
// filesystem) and writes them to downloadDir as regular files.
// Returns the host paths suitable for kexec.Load.
//
// When p.Kernel / p.Initrd are empty the helper falls back to the
// usual /boot/{vmlinuz,Image}-* glob via fs.ListDir — same
// per-distro heuristic as resolveDiskKernel used to do on the
// kernel-mounted /mnt path, but driven through the FS interface
// so it works against any pure-Go driver.
func extractAndStage(fs filesystem.Filesystem, p diskParams) (string, string, error) {
	kPath := p.Kernel
	if kPath == "" {
		path, err := pickKernelFromFS(fs)
		if err != nil {
			return "", "", err
		}
		kPath = path
	}
	iPath := p.Initrd
	if iPath == "" {
		path, err := pickInitrdFromFS(fs, kPath)
		if err != nil {
			return "", "", err
		}
		iPath = path
	}

	log.Printf("disk-fs: reading kernel %q + initrd %q from filesystem", kPath, iPath)
	kBytes, err := fs.ReadFile(kPath)
	if err != nil {
		return "", "", fmt.Errorf("read kernel %s: %w", kPath, err)
	}
	iBytes, err := fs.ReadFile(iPath)
	if err != nil {
		return "", "", fmt.Errorf("read initrd %s: %w", iPath, err)
	}

	kStaged, iStaged, err := stageBootBytes(kBytes, iBytes)
	if err != nil {
		return "", "", err
	}
	log.Printf("disk-fs: staged kernel=%d B at %s, initrd=%d B at %s", len(kBytes), kStaged, len(iBytes), iStaged)
	return kStaged, iStaged, nil
}

// pickKernelFromFS reproduces the legacy resolveDiskKernel glob
// ordering against a Go FS:
//
//	/boot/vmlinuz-*    Debian / Ubuntu / Fedora amd64 / Alpine
//	/boot/Image-*      openSUSE arm64
//	/vmlinuz-*         when fs IS the /boot partition (Fedora)
//	/Image-*           same, arm64 distros with a dedicated /boot
//
// Picks the lexicographically largest match per directory (acts as
// a proxy for "newest" given Debian-style versioning).
func pickKernelFromFS(fs filesystem.Filesystem) (string, error) {
	for _, candidate := range []struct {
		dir, prefix string
	}{
		{"/boot", "vmlinuz-"},
		{"/boot", "Image-"},
		{"/", "vmlinuz-"},
		{"/", "Image-"},
	} {
		name, ok := newestEntryByPrefix(fs, candidate.dir, candidate.prefix)
		if ok {
			return joinFSPath(candidate.dir, name), nil
		}
	}
	return "", fmt.Errorf("no kernel found at {/,/boot/}{vmlinuz-*,Image-*}")
}

// pickInitrdFromFS pairs an initrd to the picked kernel by suffix
// match — e.g. kernel "/boot/vmlinuz-6.6.9-amd64" → "/boot/initrd.img-6.6.9-amd64".
// Falls back to the largest matching initrd if the suffix-pair
// doesn't exist (a few distros ship an initrd whose name doesn't
// mirror the kernel's).
func pickInitrdFromFS(fs filesystem.Filesystem, kernel string) (string, error) {
	dir := filepathDir(kernel)
	kBase := filepathBase(kernel)
	suffix := ""
	for _, pfx := range []string{"vmlinuz-", "Image-"} {
		if len(kBase) > len(pfx) && kBase[:len(pfx)] == pfx {
			suffix = kBase[len(pfx):]
			break
		}
	}
	for _, prefix := range []string{"initrd.img-", "initramfs-", "initrd-", "initramfs."} {
		if suffix != "" {
			candidate := prefix + suffix
			if _, err := fs.Stat(joinFSPath(dir, candidate)); err == nil {
				return joinFSPath(dir, candidate), nil
			}
		}
		if name, ok := newestEntryByPrefix(fs, dir, prefix); ok {
			return joinFSPath(dir, name), nil
		}
	}
	return "", fmt.Errorf("no initrd paired with %s", kernel)
}

// newestEntryByPrefix returns the lex-largest entry in `dir`
// whose name starts with `prefix`. Wraps fs.ListDir +
// string-sort; works against any filesystem.Filesystem.
func newestEntryByPrefix(fs filesystem.Filesystem, dir, prefix string) (string, bool) {
	entries, err := fs.ListDir(dir)
	if err != nil {
		return "", false
	}
	best := ""
	for _, e := range entries {
		name := e.Name()
		if len(name) < len(prefix) || name[:len(prefix)] != prefix {
			continue
		}
		if name > best {
			best = name
		}
	}
	return best, best != ""
}

func joinFSPath(dir, name string) string {
	if dir == "" || dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

func filepathBase(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

func filepathDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == 0 {
				return "/"
			}
			return p[:i]
		}
	}
	return "/"
}
