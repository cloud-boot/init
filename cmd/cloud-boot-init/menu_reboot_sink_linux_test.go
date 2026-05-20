//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStageTargetOnESP exercises the file-staging step in isolation:
// a fake ESP directory under t.TempDir, fake "kernel" and "initrd"
// source files, the expected `<esp>/EFI/Linux/<safe>-*` outcome.
func TestStageTargetOnESP(t *testing.T) {
	esp := t.TempDir()
	src := t.TempDir()
	kSrc := filepath.Join(src, "kernel.bin")
	iSrc := filepath.Join(src, "initrd.img")
	kBody := []byte("MZ\x00\x00fake-kernel-payload")
	iBody := []byte("fake-cpio-initrd-payload")
	if err := os.WriteFile(kSrc, kBody, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(iSrc, iBody, 0o644); err != nil {
		t.Fatal(err)
	}

	espK, espI, err := stageTargetOnESP(esp, "debian-cloud", kSrc, iSrc)
	if err != nil {
		t.Fatalf("stageTargetOnESP: %v", err)
	}
	if want := `\EFI\Linux\debian-cloud-vmlinuz.efi`; espK != want {
		t.Errorf("espK = %q, want %q", espK, want)
	}
	if want := `\EFI\Linux\debian-cloud-initrd`; espI != want {
		t.Errorf("espI = %q, want %q", espI, want)
	}
	got, err := os.ReadFile(filepath.Join(esp, "EFI", "Linux", "debian-cloud-vmlinuz.efi"))
	if err != nil || string(got) != string(kBody) {
		t.Errorf("kernel copy: err=%v body mismatch", err)
	}
	got, err = os.ReadFile(filepath.Join(esp, "EFI", "Linux", "debian-cloud-initrd"))
	if err != nil || string(got) != string(iBody) {
		t.Errorf("initrd copy: err=%v body mismatch", err)
	}
}

// TestStageTargetOnESP_NoInitrd verifies the no-initrd path —
// some plan targets (debian d-i netboot, kernel-only smoke tests)
// don't carry an initrd; we should skip the copy + leave the
// espInitrd return string empty.
func TestStageTargetOnESP_NoInitrd(t *testing.T) {
	esp := t.TempDir()
	kSrc := filepath.Join(t.TempDir(), "k.bin")
	if err := os.WriteFile(kSrc, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, espI, err := stageTargetOnESP(esp, "kernel-only", kSrc, "")
	if err != nil {
		t.Fatal(err)
	}
	if espI != "" {
		t.Errorf("espI = %q, want \"\"", espI)
	}
	if _, err := os.Stat(filepath.Join(esp, "EFI", "Linux", "kernel-only-initrd")); !os.IsNotExist(err) {
		t.Errorf("expected initrd missing, got err=%v", err)
	}
}

// TestStageTargetOnESP_SanitizeName ensures slashes / spaces / etc
// in target names don't escape \EFI\Linux\.
func TestStageTargetOnESP_SanitizeName(t *testing.T) {
	esp := t.TempDir()
	kSrc := filepath.Join(t.TempDir(), "k.bin")
	if err := os.WriteFile(kSrc, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	espK, _, err := stageTargetOnESP(esp, "../escape me/.. ", kSrc, "")
	if err != nil {
		t.Fatal(err)
	}
	if want := `\EFI\Linux\.._escape_me_.._-vmlinuz.efi`; espK != want {
		t.Errorf("espK = %q, want %q", espK, want)
	}
}
