//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/cloud-boot/init/internal/kexec"
	"github.com/cloud-boot/init/internal/plan"
)

const diskMount = "/mnt"

// diskParams bundles every input runDisk needs. Both entry points — cmdline
// keys (early-boot dispatch in main.go) and plan targets with a disk{} block
// — translate to this struct so runDisk doesn't need to know the source.
type diskParams struct {
	Device  string // required, e.g. /dev/vda2
	FS      string // "" → ext4
	Kernel  string // "" → newest /boot/vmlinuz-*
	Initrd  string // "" → paired with kernel
	Cmdline string // "" → /etc/kernel/cmdline (if present), else built-in
}

// diskParamsFromTarget derives params from a plan Target whose Disk block
// is set. Target.Cmdline (HCL-supplied) seeds the new kernel's command line,
// but cloudboot.cmdline= on the UKI's own cmdline still wins so the operator
// can override an HCL choice at boot time without rebuilding the plan.
func diskParamsFromTarget(t *plan.Target, cmd map[string]string) diskParams {
	p := diskParams{
		Device:  t.Disk.Device,
		FS:      t.Disk.FS,
		Kernel:  t.Disk.Kernel,
		Initrd:  t.Disk.Initrd,
		Cmdline: t.Cmdline,
	}
	if v := cmd["cloudboot.cmdline"]; v != "" {
		p.Cmdline = v
	}
	return p
}

// diskParamsFromCmdline derives params from /proc/cmdline. Selected when the
// UKI was booted with cloudboot.disk=<device> (no plan, no network).
//
//	cloudboot.disk=<device>          device to mount, e.g. /dev/vda2 (required)
//	cloudboot.disk.fs=<type>         filesystem type (default ext4)
//	cloudboot.disk.kernel=<path>     explicit kernel path on the mount
//	cloudboot.disk.initrd=<path>     explicit initrd path on the mount
//	cloudboot.cmdline=<text>         cmdline forwarded to the new kernel
func diskParamsFromCmdline(cmd map[string]string) diskParams {
	return diskParams{
		Device:  cmd["cloudboot.disk"],
		FS:      cmd["cloudboot.disk.fs"],
		Kernel:  cmd["cloudboot.disk.kernel"],
		Initrd:  cmd["cloudboot.disk.initrd"],
		Cmdline: cmd["cloudboot.cmdline"],
	}
}

// runDisk implements the "boot the distro from a local virtio-blk disk"
// path. It mounts the device read-only, locates a distro kernel + initrd
// pair under /boot, and kexecs into them.
//
// The cmdline handed to the new kernel comes from p.Cmdline; if empty, it
// falls back to /etc/kernel/cmdline on the mounted disk; if that's missing
// too, the kernel uses its built-in CONFIG_CMDLINE.
func runDisk(p diskParams) error {
	if p.Device == "" {
		return fmt.Errorf("runDisk: missing device")
	}
	if p.FS == "" {
		p.FS = "ext4"
	}

	// ZFS is special: p.Device is a dataset path
	// (`rpool/ROOT/pve-1`), not a /dev/<name>, and mounting it
	// requires modprobe zfs + zpool import + zfs mount via
	// userspace zfsutils — see runDiskZFS for the full sequence.
	// On success the dataset is mounted at diskMount and we fall
	// through to runDiskMounted; on failure the precondition
	// errors are surfaced verbatim.
	if p.FS == "zfs" {
		if err := runDiskZFS(p); err != nil {
			return err
		}
		return runDiskMounted(p)
	}

	// Resolve LABEL=… / UUID=… / PARTLABEL=… / PARTUUID=… to a real
	// /dev/<name>. Same syntax as the kernel's `root=`. Literal /dev
	// paths pass through unchanged.
	resolved, err := resolveBlockDevice(p.Device)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", p.Device, err)
	}
	if resolved != p.Device {
		log.Printf("resolved %s → %s", p.Device, resolved)
	}

	if err := os.MkdirAll(diskMount, 0o755); err != nil {
		return err
	}
	log.Printf("mounting %s (%s) on %s read-only", resolved, p.FS, diskMount)
	if err := unix.Mount(resolved, diskMount, p.FS, unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("mount %s: %w", resolved, err)
	}
	return runDiskMounted(p)
}

// runDiskMounted finishes the disk-target boot sequence once the
// disk (or ZFS dataset) is mounted at `diskMount`. Locates the
// kernel + initrd + cmdline on the mount, kexecs into them, and
// arranges an unmount on the non-happy path so the disk doesn't
// stay pinned.
//
// Shared by every fs= branch (ext4 / xfs / btrfs / zfs); the only
// thing the caller varies is HOW the mount got there.
func runDiskMounted(p diskParams) error {
	// We pass nothing to the next kernel via diskMount itself —
	// kexec_file_load has the file content in memory by the time
	// Boot() runs. Unmount on any non-boot exit path so userspace
	// doesn't keep the disk pinned.
	defer func() { _ = unix.Unmount(diskMount, 0) }()

	kPath, err := resolveDiskKernel(p.Kernel)
	if err != nil {
		return err
	}
	iPath, err := resolveDiskInitrd(p.Initrd, kPath)
	if err != nil {
		return err
	}
	kArgs := resolveDiskCmdline(p.Cmdline)

	log.Printf("kexec load (kernel=%s initrd=%s cmdline=%q)", kPath, iPath, kArgs)
	if err := kexec.Load(kPath, iPath, kArgs); err != nil {
		return fmt.Errorf("kexec load: %w", err)
	}
	log.Printf("kexec boot")
	return kexec.Boot()
}

// resolveDiskKernel picks the kernel path on the mounted disk: either
// an explicit override, or the newest file matching one of:
//
//	/boot/vmlinuz-*     Debian / Ubuntu / Fedora amd64 / Alpine
//	/boot/Image-*       openSUSE arm64 (kernel named "Image-…-default")
//	/vmlinuz-*          when the mount IS the /boot partition (Fedora)
//	/Image-*            same, arm64 distros with a dedicated /boot
//
// The four globs are tried in order; first non-empty match wins.
// Cloud-boot-init's mount step always succeeds before we get here, so
// every glob targets the actual mount point — we just don't yet know
// whether the user gave us a rootfs (kernel under /boot) or a
// dedicated /boot partition (kernel at the root of the mount).
func resolveDiskKernel(override string) (string, error) {
	if override != "" {
		return mountAbs(override), nil
	}
	for _, glob := range []string{
		filepath.Join(diskMount, "boot", "vmlinuz-*"),
		filepath.Join(diskMount, "boot", "Image-*"),
		filepath.Join(diskMount, "vmlinuz-*"),
		filepath.Join(diskMount, "Image-*"),
	} {
		path, err := pickNewestFile(glob)
		if err == nil && path != "" {
			return path, nil
		}
	}
	return "", fmt.Errorf("no kernel found at %s/{boot/,}{vmlinuz-*,Image-*}", diskMount)
}

// resolveDiskInitrd mirrors resolveDiskKernel for the initrd, falling back
// to pairing by the kernel's version suffix.
func resolveDiskInitrd(override, kernel string) (string, error) {
	if override != "" {
		return mountAbs(override), nil
	}
	return pairInitrdWithKernel(kernel, fileExists)
}

// resolveDiskCmdline returns the cmdline to hand to the new kernel: the
// explicit override if set, else /mnt/etc/kernel/cmdline if it exists, else
// the empty string (the kernel falls back to its built-in CONFIG_CMDLINE).
func resolveDiskCmdline(override string) string {
	if override != "" {
		return override
	}
	b, err := os.ReadFile(filepath.Join(diskMount, "etc", "kernel", "cmdline"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// mountAbs interprets a user-supplied path either as an absolute path
// rooted at the diskMount ("/boot/vmlinuz-X" → "/mnt/boot/vmlinuz-X") or
// as already-rooted ("/mnt/boot/...") if the caller did the math themselves.
func mountAbs(p string) string {
	if strings.HasPrefix(p, diskMount+"/") || p == diskMount {
		return p
	}
	return filepath.Join(diskMount, p)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
