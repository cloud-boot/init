//go:build linux

// ZFS-on-root branch of the disk target path.
//
// Boots an existing ZFS-rooted distro (Proxmox VE, Ubuntu Server
// ZSYS, …) by importing its pool, mounting the root dataset, and
// reading /boot/vmlinuz + initrd from the mounted path. The
// reboot sink then stages those onto the cache disk ESP and
// flips Boot0001 — same chain as the ext4/xfs/btrfs path, just
// with a different mount mechanism.
//
// Requirements (must be in place for this code to actually run
// without bailing out):
//
//   1. Kernel built with CONFIG_MODULES=y AND the OpenZFS .ko
//      files installed under /lib/modules/<uname -r>/. The
//      `disk-zfs` kernel variant (Dockerfile.arm64-disk-zfs)
//      handles this — base `disk` kernel does NOT support ZFS.
//   2. zfsutils-linux (zpool + zfs binaries) bundled in the
//      initramfs. NOT yet wired — the cloud-boot build pipeline
//      will need a `--zfs-userspace=<path-to-tarball>` flag (or
//      a separate Dockerfile that cross-compiles them) before
//      this branch is functional.
//
// See memory:zfs-root-support for the broader design + the
// remaining wire-up.

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

// runDiskZFS handles the fs="zfs" branch of a Disk target. Until
// the full bundling lands, it surfaces a clear error pointing the
// operator at the missing pieces — better than letting a syscall
// fail with a cryptic ENODEV / EINVAL when the operator wired
// `fs = "zfs"` against the wrong kernel variant.
func runDiskZFS(p diskParams) error {
	// Sanity: confirm the zfs kernel module is available. The
	// disk-zfs kernel ships /lib/modules/<ver>/extra/zfs.ko (or
	// similar). Absence = wrong kernel variant.
	if !zfsModuleAvailable() {
		return fmt.Errorf("zfs target %q: kernel has no zfs module — rebuild with Dockerfile.arm64-disk-zfs and re-stage", p.Device)
	}
	// Sanity: zpool / zfs userspace binaries.
	for _, bin := range []string{"zpool", "zfs"} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("zfs target %q: %s not in PATH — zfsutils-linux bundling in initramfs is not yet wired (see memory:zfs-root-support)", p.Device, bin)
		}
	}

	// modprobe zfs (no-op if already loaded — modprobe handles that).
	if err := runCmd("modprobe", "zfs"); err != nil {
		return fmt.Errorf("modprobe zfs: %w", err)
	}

	// Extract pool name from the dataset path "<pool>/<rest>".
	pool := datasetPool(p.Device)
	if pool == "" {
		return fmt.Errorf("zfs target: device %q must be a dataset path (e.g. rpool/ROOT/pve-1)", p.Device)
	}

	// Import the pool without auto-mounting any filesystems (we'll
	// mount only the root dataset manually). -d /dev/disk/by-id
	// uses stable vdev identifiers across reboots.
	log.Printf("zfs: importing pool %q (-N = no auto-mount)", pool)
	if err := runCmd("zpool", "import", "-N", "-d", "/dev/disk/by-id", pool); err != nil {
		// Some setups don't have /dev/disk/by-id populated; retry
		// with a broader search path.
		if err2 := runCmd("zpool", "import", "-N", "-d", "/dev", pool); err2 != nil {
			return fmt.Errorf("zpool import %s: %w (fallback also failed: %v)", pool, err, err2)
		}
	}

	// Mount the target dataset at /mnt/disk so the reboot sink can
	// read /boot/vmlinuz + initrd as if it were any other root fs.
	// `zfs set canmount=noauto` first so future imports don't
	// re-mount automatically on top of our manual mount.
	_ = runCmd("zfs", "set", "canmount=noauto", p.Device)
	if err := os.MkdirAll(diskMount, 0o755); err != nil {
		return err
	}
	log.Printf("zfs: mounting dataset %q at %s", p.Device, diskMount)
	if err := runCmd("mount", "-t", "zfs", "-o", "ro", p.Device, diskMount); err != nil {
		return fmt.Errorf("mount zfs %s: %w", p.Device, err)
	}

	// Reboot sink expects diskMount to be populated with /boot/
	// content — same contract as ext4/xfs/btrfs. The caller
	// continues from here exactly as for those filesystems.
	return runDiskMounted(p, diskMount)
}

// zfsModuleAvailable returns true if either zfs is already loaded
// (visible in /proc/modules) or the module file exists somewhere
// under /lib/modules and could be modprobed.
func zfsModuleAvailable() bool {
	if data, err := os.ReadFile("/proc/modules"); err == nil {
		// Format: "zfs <size> <refcount> ..." — match the
		// module name at the start of a line.
		for _, line := range splitLines(data) {
			if startsWith(line, "zfs ") {
				return true
			}
		}
	}
	// Walk /lib/modules looking for a zfs.ko anywhere under the
	// kernel's modules tree. depmod-managed layouts vary
	// (zfs.ko under extra/, kernel/fs/, or pre-staged for our
	// builder) — a recursive name match catches all of them.
	found := false
	_ = walkDir("/lib/modules", func(p string) {
		if endsWith(p, "/zfs.ko") || endsWith(p, "/zfs.ko.xz") || endsWith(p, "/zfs.ko.zst") {
			found = true
		}
	})
	return found
}

func datasetPool(dataset string) string {
	for i, c := range dataset {
		if c == '/' {
			return dataset[:i]
		}
	}
	return dataset
}

func runCmd(cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}

func splitLines(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}

func startsWith(s, prefix string) bool { return len(s) >= len(prefix) && s[:len(prefix)] == prefix }
func endsWith(s, suffix string) bool   { return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix }

func walkDir(root string, fn func(string)) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		p := root + "/" + e.Name()
		if e.IsDir() {
			_ = walkDir(p, fn)
		} else {
			fn(p)
		}
	}
	return nil
}

// runDiskMounted is the shared post-mount step that ext4/xfs/btrfs
// also use (refactored out of runDisk in a follow-up). For now
// it's a forward declaration — the actual logic lives at the
// bottom of runDisk and will be lifted out when the ZFS branch
// goes live. Until that refactor, this returns a clear error
// telling the operator the ZFS path isn't yet wired.
func runDiskMounted(p diskParams, mountpoint string) error {
	return fmt.Errorf("zfs target %q: post-mount kernel+initrd staging not yet refactored (will share path with ext4/xfs/btrfs once disk_linux.go's mounted-disk logic is extracted)", p.Device)
}
