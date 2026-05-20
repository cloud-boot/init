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
	"log"
)

// rebootSink is the menu-then-reboot replacement for kexec.Load +
// kexec.Boot. The full implementation comes in incremental commits;
// for now this scaffolding just logs the intent so the dispatch
// branch in main.go can be exercised before the heavy lifting
// (ESP discovery, efivarfs writes) lands.
func rebootSink(targetName, kPath, iPath, kArgs string) error {
	log.Printf("reboot-sink: target=%s kernel=%s initrd=%s", targetName, kPath, iPath)
	log.Printf("reboot-sink: cmdline=%q", kArgs)
	log.Printf("reboot-sink: TODO — copy to ESP, write Boot0001, reboot(2)")
	// Hang here for now so the rest of the test harness still sees
	// "menu reached its sink without exploding". Subsequent commits
	// replace this with the real ESP+NVRAM+reboot work.
	return fmt.Errorf("reboot-sink not yet implemented past the scaffolding (see memory:uki-menu-then-reboot)")
}
