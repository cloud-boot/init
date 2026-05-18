//go:build linux

// Package kexec wraps the kexec_file_load(2) syscall and the reboot(2) trigger.
package kexec

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	flagKexecFileNoInitramfs = 0x4
	rebootCmdKexec           = 0x45584543
)

// Load stages the given kernel + optional initrd + cmdline for kexec.
//
// EFI zboot kernels (e.g. Alpine's vmlinuz-virt) are transparently
// unwrapped first — arm64's kexec_file_load only accepts a raw Image
// (it probes for ARM64_IMAGE_MAGIC at offset 56) and would reject the
// PE wrapper with EINVAL. See zboot_linux.go for the format details.
func Load(kernelPath, initrdPath, cmdline string) error {
	unwrapped, err := MaybeUnwrapZBoot(kernelPath)
	if err != nil {
		return fmt.Errorf("zboot unwrap: %w", err)
	}
	if unwrapped != kernelPath {
		defer os.Remove(unwrapped)
		kernelPath = unwrapped
	}
	kf, err := os.Open(kernelPath)
	if err != nil {
		return fmt.Errorf("open kernel: %w", err)
	}
	defer kf.Close()

	var initrdFD int = -1
	var flags uintptr = flagKexecFileNoInitramfs
	if initrdPath != "" {
		f, err := os.Open(initrdPath)
		if err != nil {
			return fmt.Errorf("open initrd: %w", err)
		}
		defer f.Close()
		initrdFD = int(f.Fd())
		flags = 0
	}

	cl := append([]byte(cmdline), 0)
	clLen := uintptr(len(cl))
	clPtr := unsafe.Pointer(&cl[0])

	_, _, errno := syscall.Syscall6(
		unix.SYS_KEXEC_FILE_LOAD,
		kf.Fd(),
		uintptr(initrdFD),
		clLen,
		uintptr(clPtr),
		flags,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("kexec_file_load: %w", errno)
	}
	return nil
}

// Boot triggers the staged kernel. Does not return on success.
func Boot() error {
	syscall.Sync()
	if err := unix.Reboot(rebootCmdKexec); err != nil {
		return fmt.Errorf("reboot(KEXEC): %w", err)
	}
	return nil
}
