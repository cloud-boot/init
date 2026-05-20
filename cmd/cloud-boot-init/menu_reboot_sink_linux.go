//go:build linux

// Boot sink that doesn't call kexec.
//
// On Apple Virtualization.framework on arm64, kexec_file_load traps
// silently (see memory:uki-vz-constraint). The existing kexec sink
// runs fine under QEMU/OVMF but hangs the VM under VZ. To make
// cloud-boot work in production-VZ deployments we let the user
// switch to a `reboot` sink via the cmdline knob
//
//	cloudboot.exit=reboot
//
// In this mode, after the plan is resolved and the target's
// kernel+initrd are pulled / located, this sink:
//
//  1. Locates the FAT EFI System Partition and mounts it read-write.
//  2. Copies the target's vmlinuz + initrd onto the ESP at
//     `\EFI\Linux\<target>-vmlinuz.efi` + `\EFI\Linux\<target>-initrd`.
//  3. Writes a UEFI Boot0001 LoadOption pointing at the new vmlinuz
//     with `initrd=\EFI\Linux\<target>-initrd <cmdline>` as the
//     OptionalData (the EFI stub reads this).
//  4. Updates BootOrder to put Boot0001 first.
//  5. Calls reboot(2). Firmware restarts the VM and the EFI boot
//     manager honours the new BootOrder, loading the target's UKI
//     directly via standard LoadImage+StartImage — a code path VZ
//     supports natively (it's the same one vfkit's --bootloader efi
//     uses for the menu UKI on the first boot).
//
// No kexec anywhere in this chain. Everything below ExitBootServices
// runs in standard Linux PID 1 context.
//
// See memory:uki-menu-then-reboot for the full architecture rationale.

package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

// rebootSink is the menu-then-reboot replacement for kexec.Load +
// kexec.Boot. Built incrementally — current scope: ESP discovery
// + kernel/initrd copy. Subsequent commits write Boot####/BootOrder
// and trigger reboot(2).
//
// On success the firmware can find the chosen target's UKI at
// \EFI\Linux\<sanitized-target>-vmlinuz.efi (matches the
// systemd-boot layout convention closely enough that an operator
// inspecting the ESP with `mdir` doesn't get surprised).
func rebootSink(targetName, kPath, iPath, kArgs string) error {
	log.Printf("reboot-sink: target=%s kernel=%s initrd=%s", targetName, kPath, iPath)
	log.Printf("reboot-sink: cmdline=%q", kArgs)

	esp, err := findAndMountESP()
	if err != nil {
		return fmt.Errorf("esp: %w", err)
	}
	log.Printf("reboot-sink: ESP mounted at %s", esp)

	espKernel, espInitrd, err := stageTargetOnESP(esp, targetName, kPath, iPath)
	if err != nil {
		return fmt.Errorf("stage target: %w", err)
	}
	log.Printf("reboot-sink: staged kernel=%s initrd=%s", espKernel, espInitrd)

	// Build the OptionalData payload — the EFI stub reads
	// LoadedImage.LoadOptions as a UTF-16LE string and treats it as
	// the kernel cmdline. For initrd-bearing targets we prepend the
	// stub's own `initrd=...` directive so it loads the initrd from
	// the same FAT volume via SimpleFileSystem.
	cmdline := kArgs
	if espInitrd != "" {
		cmdline = "initrd=" + espInitrd + " " + kArgs
	}
	desc := "cloud-boot " + targetName
	lo := encodeLoadOption(desc, espKernel, cmdline)
	if err := writeEFIVar("Boot0001", efiAttrsNVBSRT, lo); err != nil {
		return fmt.Errorf("write Boot0001: %w", err)
	}
	log.Printf("reboot-sink: Boot0001 written (%d bytes)", len(lo))
	if err := prependToBootOrder(0x0001); err != nil {
		return fmt.Errorf("update BootOrder: %w", err)
	}
	log.Printf("reboot-sink: BootOrder prefixed with 0001")

	log.Printf("reboot-sink: TODO — reboot(2)")
	return fmt.Errorf("reboot-sink not yet implemented past NVRAM writes (see memory:uki-menu-then-reboot)")
}

// stageTargetOnESP copies the resolved kernel and initrd into
// `<esp>/EFI/Linux/<safeName>-vmlinuz.efi` + `<safeName>-initrd`.
// Returns the ESP-relative paths (with backslashes, the form the
// LoadOption needs) so commit 4 can drop them straight into the
// FilePath element of the device path.
//
// The kernel is opened up to its full size (cloud-boot init has
// already AllocatePool'd it earlier, so the source is a regular
// file on the tmpfs initrd). io.Copy uses a 32 KiB buffer; with
// kernels at ~10-20 MiB and initrds at ~100-500 MiB the copy
// completes in well under a second on virtio-blk.
func stageTargetOnESP(esp, targetName, kPath, iPath string) (espKernel, espInitrd string, err error) {
	safe := sanitize(targetName)
	linuxDir := filepath.Join(esp, "EFI", "Linux")
	if err := os.MkdirAll(linuxDir, 0o755); err != nil {
		return "", "", fmt.Errorf("mkdir %s: %w", linuxDir, err)
	}
	kHost := filepath.Join(linuxDir, safe+"-vmlinuz.efi")
	iHost := filepath.Join(linuxDir, safe+"-initrd")
	if err := copyFileOnto(kPath, kHost); err != nil {
		return "", "", fmt.Errorf("copy kernel: %w", err)
	}
	if iPath != "" {
		if err := copyFileOnto(iPath, iHost); err != nil {
			return "", "", fmt.Errorf("copy initrd: %w", err)
		}
	}
	// LoadOption FilePath uses backslashes, ESP-rooted paths.
	espKernel = `\EFI\Linux\` + safe + `-vmlinuz.efi`
	espInitrd = `\EFI\Linux\` + safe + `-initrd`
	if iPath == "" {
		espInitrd = ""
	}
	return espKernel, espInitrd, nil
}

// copyFileOnto is a straightforward read-and-write. Permissions on
// the FAT side are notional (VFAT serves files with a fixed mode
// derived from the mount options), so we don't bother chmod'ing
// after close.
func copyFileOnto(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
