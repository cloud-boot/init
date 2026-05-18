//go:build linux

package kexec

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// fakeARM64Image returns a 64-byte buffer with the arm64 image magic
// `ARM\x64` at offset 56 — enough to round-trip through MaybeUnwrapZBoot
// and let the caller assert the unwrapped output is what arm64
// kexec_file_load's image_probe() would accept.
func fakeARM64Image() []byte {
	b := make([]byte, 64)
	copy(b[56:60], []byte{0x41, 0x52, 0x4D, 0x64})
	return b
}

// wrapZBoot builds the canonical zboot PE header in front of an already-
// compressed payload, with the given compression-type label.
func wrapZBoot(t *testing.T, compType string, compressed []byte) []byte {
	t.Helper()
	if len(compType) > 32 {
		t.Fatalf("compType too long: %d > 32", len(compType))
	}
	var hdr [56]byte
	copy(hdr[0:4], []byte{0x4D, 0x5A, 0, 0})       // "MZ\0\0"
	copy(hdr[4:8], []byte{0x7A, 0x69, 0x6D, 0x67}) // "zimg"
	binary.LittleEndian.PutUint32(hdr[8:12], 56)    // payload follows hdr
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(compressed)))
	copy(hdr[24:56], []byte(compType))
	return append(hdr[:], compressed...)
}

func writeFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMaybeUnwrapZBoot_Gzip(t *testing.T) {
	want := fakeARM64Image()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(want); err != nil {
		t.Fatal(err)
	}
	gz.Close()
	src := writeFile(t, t.TempDir(), "k.efi", wrapZBoot(t, "gzip", buf.Bytes()))
	out, err := MaybeUnwrapZBoot(src)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(out)
	if out == src {
		t.Fatal("expected a new tempfile path, got input path")
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("decompressed mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

func TestMaybeUnwrapZBoot_Zstd(t *testing.T) {
	want := fakeARM64Image()
	enc, _ := zstd.NewWriter(nil)
	compressed := enc.EncodeAll(want, nil)
	enc.Close()
	src := writeFile(t, t.TempDir(), "k.efi", wrapZBoot(t, "zstd", compressed))
	out, err := MaybeUnwrapZBoot(src)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(out)
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("decompressed mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

func TestMaybeUnwrapZBoot_NotZBoot(t *testing.T) {
	// A raw arm64 Image (no zboot wrapper) should pass through unchanged.
	src := writeFile(t, t.TempDir(), "raw.img", fakeARM64Image())
	out, err := MaybeUnwrapZBoot(src)
	if err != nil {
		t.Fatal(err)
	}
	if out != src {
		t.Errorf("expected pass-through, got %q", out)
	}
}

func TestMaybeUnwrapZBoot_TooShort(t *testing.T) {
	// A file shorter than the 56-byte header isn't zboot — just pass through.
	src := writeFile(t, t.TempDir(), "short.bin", []byte{0x4D, 0x5A, 0, 0})
	out, err := MaybeUnwrapZBoot(src)
	if err != nil {
		t.Fatal(err)
	}
	if out != src {
		t.Errorf("expected pass-through, got %q", out)
	}
}

func TestMaybeUnwrapZBoot_UnsupportedCompression(t *testing.T) {
	// xz / lzma / lz4 / lzo aren't in our decoder set; forging one
	// should surface a clear error instead of garbling silently. If
	// you ever hit this in production with a real kernel, the comp
	// type names what to add to zboot_linux.go.
	src := writeFile(t, t.TempDir(), "xz.efi", wrapZBoot(t, "xz", []byte{0xfd, '7', 'z', 'X', 'Z', 0}))
	_, err := MaybeUnwrapZBoot(src)
	if err == nil || !strings.Contains(err.Error(), "unsupported compression") {
		t.Errorf("want unsupported-compression error, got %v", err)
	}
}

func TestMaybeUnwrapZBoot_OpenError(t *testing.T) {
	if _, err := MaybeUnwrapZBoot(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("expected open error")
	}
}

func TestMaybeUnwrapZBoot_BadGzip(t *testing.T) {
	src := writeFile(t, t.TempDir(), "junk.efi", wrapZBoot(t, "gzip", []byte("not a gzip stream")))
	_, err := MaybeUnwrapZBoot(src)
	if err == nil || !strings.Contains(err.Error(), "gzip") {
		t.Errorf("want gzip error, got %v", err)
	}
}
