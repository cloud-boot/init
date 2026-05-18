package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPickNewestFile(t *testing.T) {
	dir := t.TempDir()
	older := filepath.Join(dir, "vmlinuz-6.6.0-1-amd64")
	newer := filepath.Join(dir, "vmlinuz-6.6.0-2-amd64")
	for _, p := range []string{older, newer} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Backdate `older`.
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(older, old, old); err != nil {
		t.Fatal(err)
	}

	got, err := pickNewestFile(filepath.Join(dir, "vmlinuz-*"))
	if err != nil {
		t.Fatal(err)
	}
	if got != newer {
		t.Fatalf("pickNewestFile = %s, want %s", got, newer)
	}
}

func TestPickNewestFile_NoMatch(t *testing.T) {
	if _, err := pickNewestFile(filepath.Join(t.TempDir(), "nope-*")); err == nil {
		t.Fatal("expected error on no match")
	}
}

func TestPickNewestFile_BadGlob(t *testing.T) {
	if _, err := pickNewestFile("[]"); err == nil {
		t.Fatal("expected error on malformed glob")
	}
}

func TestPairInitrdWithKernel(t *testing.T) {
	const kernel = "/mnt/boot/vmlinuz-6.6.0-2-amd64"
	cases := []struct {
		name    string
		present map[string]bool
		want    string
		wantErr bool
	}{
		{
			name:    "debian style",
			present: map[string]bool{"/mnt/boot/initrd.img-6.6.0-2-amd64": true},
			want:    "/mnt/boot/initrd.img-6.6.0-2-amd64",
		},
		{
			name:    "fedora style",
			present: map[string]bool{"/mnt/boot/initramfs-6.6.0-2-amd64.img": true},
			want:    "/mnt/boot/initramfs-6.6.0-2-amd64.img",
		},
		{
			name:    "arch style",
			present: map[string]bool{"/mnt/boot/initrd-6.6.0-2-amd64": true},
			want:    "/mnt/boot/initrd-6.6.0-2-amd64",
		},
		{
			name:    "debian wins over fedora when both present",
			present: map[string]bool{"/mnt/boot/initrd.img-6.6.0-2-amd64": true, "/mnt/boot/initramfs-6.6.0-2-amd64.img": true},
			want:    "/mnt/boot/initrd.img-6.6.0-2-amd64",
		},
		{
			name:    "none present",
			present: map[string]bool{},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := pairInitrdWithKernel(kernel, func(p string) bool { return c.present[p] })
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
			if !c.wantErr && got != c.want {
				t.Fatalf("got %s, want %s", got, c.want)
			}
		})
	}
}

func TestPairInitrdWithKernel_BadKernelName(t *testing.T) {
	_, err := pairInitrdWithKernel("/mnt/boot/whatever", func(string) bool { return true })
	if err == nil {
		t.Fatal("expected error on non-vmlinuz- name")
	}
}
