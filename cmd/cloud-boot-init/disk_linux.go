//go:build linux

package main

import (
	"fmt"
	"log"

	"github.com/cloud-boot/init/internal/kexec"
	"github.com/cloud-boot/init/internal/plan"
)

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

	// ZFS keeps its own opener — Disk.Device is a dataset path,
	// not a /dev/<name>, and pool discovery + dataset traversal
	// can't share resolveBlockDevice. runDiskZFS stages kernel
	// and initrd under downloadDir, then jumps straight to the
	// kexec dispatch via kexecStaged.
	if p.FS == "zfs" {
		return runDiskZFS(p)
	}

	// Everything else (ext4 / xfs / btrfs) goes through the
	// unified pure-Go path: resolve LABEL/UUID → /dev/<name>,
	// open with the right go-filesystems driver, extract kernel
	// and initrd as bytes, stage under downloadDir, kexec. No
	// unix.Mount(2). Kernel doesn't need CONFIG_*_FS for these
	// filesystems anymore.
	resolved, err := resolveBlockDevice(p.Device)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", p.Device, err)
	}
	if resolved != p.Device {
		log.Printf("resolved %s → %s", p.Device, resolved)
	}

	fs, err := openFS(p, resolved)
	if err != nil {
		return err
	}
	defer fs.Close()

	kPath, iPath, blsOpts, err := extractAndStage(fs, p)
	if err != nil {
		return err
	}
	// Prepend BLS-supplied per-generation cmdline tokens (e.g.
	// NixOS's init=/nix/store/<hash>-init) BEFORE p.Cmdline so the
	// kernel's later-wins parsing lets the operator's
	// cloudboot.cmdline= override individual tokens if needed.
	if blsOpts != "" {
		merged := blsOpts
		if p.Cmdline != "" {
			merged += " " + p.Cmdline
		}
		log.Printf("disk-fs: merged cmdline = %q  (BLS=%q + override=%q)", merged, blsOpts, p.Cmdline)
		p.Cmdline = merged
	}
	return kexecStaged(p, kPath, iPath)
}

// kexecStaged hands two staged-under-downloadDir paths to
// kexec.Load + Boot. Cmdline resolution: explicit override on
// the target wins; otherwise empty (the chained kernel falls
// back to its built-in CONFIG_CMDLINE — we no longer can read
// /etc/kernel/cmdline because the source disk isn't mounted).
//
// Shared by every disk-fs= branch.
func kexecStaged(p diskParams, kPath, iPath string) error {
	kArgs := p.Cmdline

	log.Printf("kexec load (kernel=%s initrd=%s cmdline=%q)", kPath, iPath, kArgs)
	if err := kexec.Load(kPath, iPath, kArgs); err != nil {
		return fmt.Errorf("kexec load: %w", err)
	}
	log.Printf("kexec boot")
	return kexec.Boot()
}

// resolveDiskKernel picks the kernel path on the mounted disk: either
// (The legacy resolveDiskKernel / resolveDiskInitrd / resolveDiskCmdline
// + mountAbs / fileExists helpers were removed when runDisk pivoted from
// unix.Mount + filesystem syscalls to the pure-Go go-filesystems drivers
// — see disk_fs_linux.go for the replacement. pickNewestFile +
// pairInitrdWithKernel remain in helpers.go because diskParamsFromCmdline-
// flow tests still exercise them.)
