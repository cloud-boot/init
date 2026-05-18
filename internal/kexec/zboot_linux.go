//go:build linux

package kexec

import (
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// MaybeUnwrapZBoot detects an EFI zboot wrapper at kernelPath and, if
// present, extracts the inner Linux kernel image to a sibling tempfile
// and returns its path. If the file is not a zboot, the original path
// is returned unchanged.
//
// EFI zboot (drivers/firmware/efi/libstub/zboot-header.S) layout:
//
//	offset 0  : "MZ\0\0"
//	offset 4  : "zimg"
//	offset 8  : u32 payload_offset   (start of compressed payload)
//	offset 12 : u32 payload_size     (compressed bytes)
//	offset 16 : u32 reserved[2]
//	offset 24 : char compression_type[32]   "gzip" | "zstd" | "xz" | …
//
// arm64's kexec_file_load doesn't understand zboot — its image_probe()
// looks for ARM64_IMAGE_MAGIC at offset 56 of a raw Image header and
// rejects the zboot wrapper outright (EINVAL). By decompressing in the
// init userspace we can reuse stock netboot kernels (Alpine, RHEL, …)
// that ship exclusively as zboot today.
//
// Supported compressions — the only two mainline's Makefile.zboot can
// emit since ~6.7:
//
//	gzip   — default choice (Alpine, Debian, most distros)
//	zstd   — selected by CONFIG_KERNEL_ZSTD (Fedora, recent Ubuntu, RHEL)
//
// xz / lzma / lzo / lz4 are intentionally not implemented: mainline
// dropped them as zboot choices, no current distro ships them in zboot
// form, and the savings vs zstd are nil (xz/lzma are slightly smaller
// but much slower to decompress; lz4/lzo are faster but compress
// significantly worse — neither matters for a one-shot kernel decode).
// If a real zboot image with one of these ever shows up the error
// message names the type so we can add support in 5 minutes.
//
// Note: xz / lzma / lzo / lz4 also exist as separate `Image.<ext>`
// build targets for U-Boot and friends. Those are *raw* compressed
// Image files, not PE-wrapped zboot, and bypass this function entirely
// (no `zimg` magic at offset 4 → pass-through).
func MaybeUnwrapZBoot(kernelPath string) (string, error) {
	f, err := os.Open(kernelPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var hdr [56]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		// Too short to even be zboot — let the caller try kexec
		// directly so the original syscall error surfaces.
		return kernelPath, nil
	}
	if string(hdr[0:4]) != "MZ\x00\x00" || string(hdr[4:8]) != "zimg" {
		return kernelPath, nil
	}
	payloadOff := binary.LittleEndian.Uint32(hdr[8:12])
	payloadSize := binary.LittleEndian.Uint32(hdr[12:16])
	comp := strings.TrimRight(string(hdr[24:56]), "\x00")

	if _, err := f.Seek(int64(payloadOff), io.SeekStart); err != nil {
		return "", fmt.Errorf("zboot: seek payload @0x%x: %w", payloadOff, err)
	}
	payload := io.LimitReader(f, int64(payloadSize))

	var src io.Reader
	switch comp {
	case "gzip":
		gz, err := gzip.NewReader(payload)
		if err != nil {
			return "", fmt.Errorf("zboot/gzip: %w", err)
		}
		defer gz.Close()
		src = gz
	case "zstd":
		// klauspost/compress/zstd: pure-Go decoder. The trailing
		// uncompressed-size suffix that the kernel's zboot
		// Makefile.zboot appends after the zstd frame ("zstd22_with_size"
		// — 4 extra little-endian bytes) is harmless: io.LimitReader caps
		// reads to payload_size, and the zstd decoder stops at the end of
		// its own frame before getting to the suffix.
		zd, err := zstd.NewReader(payload)
		if err != nil {
			return "", fmt.Errorf("zboot/zstd: %w", err)
		}
		defer zd.Close()
		src = zd
	default:
		return "", fmt.Errorf("zboot: unsupported compression %q (need gzip or zstd)", comp)
	}

	out, err := os.CreateTemp("", "kernel-zboot-*.img")
	if err != nil {
		return "", fmt.Errorf("zboot: tempfile: %w", err)
	}
	defer func() {
		if err != nil {
			os.Remove(out.Name())
		}
	}()
	n, err := io.Copy(out, src)
	if err != nil {
		out.Close()
		return "", fmt.Errorf("zboot: decompress (%d bytes written): %w", n, err)
	}
	if err := out.Close(); err != nil {
		return "", fmt.Errorf("zboot: close: %w", err)
	}
	return out.Name(), nil
}
