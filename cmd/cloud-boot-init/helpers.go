// Helpers that have no platform-specific dependencies. Lifted out of
// main.go so they can be exercised by unit tests on any OS — the rest of
// cloud-boot-init lives behind `//go:build linux`.
package main

import (
	"compress/gzip"
	"io"
	"os"
	"strings"

	"github.com/cloud-boot/init/pkg/cpio"
	"github.com/cloud-boot/init/pkg/oci"
)

// readCmdline parses /proc/cmdline as a map of key=value tokens. Bare flags
// (no '=') become key="1". It is a thin wrapper around readCmdlineFile and
// only exists so tests can target the parsing logic without mocking /proc.
func readCmdline() (map[string]string, error) {
	return readCmdlineFile("/proc/cmdline")
}

func readCmdlineFile(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, tok := range splitCmdline(string(b)) {
		if i := strings.IndexByte(tok, '='); i >= 0 {
			out[tok[:i]] = tok[i+1:]
		} else {
			out[tok] = "1"
		}
	}
	return out, nil
}

// splitCmdline tokenises a kernel command line, respecting double-quoted
// values so that `console="ttyS0,115200n8"` arrives as a single token.
func splitCmdline(s string) []string {
	var out []string
	var cur strings.Builder
	q := false
	for _, r := range s {
		switch {
		case r == '"':
			q = !q
		case (r == ' ' || r == '\n' || r == '\t') && !q:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// sanitize replaces any rune outside [A-Za-z0-9._-] with '_'. Used to derive
// safe filenames from digest values.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			return r
		}
		return '_'
	}, s)
}

// resolveKind maps an OCI media type (or, as a fallback, a layer "title"
// annotation) to one of the boot artefact roles cloud-boot-init understands.
func resolveKind(mediaType, title string) string {
	switch mediaType {
	case oci.MediaTypeKernel:
		return "kernel"
	case oci.MediaTypeInitrd:
		return "initrd"
	case oci.MediaTypeModules:
		return "modules"
	case oci.MediaTypeModloop:
		return "modloop"
	case oci.MediaTypeApkovl:
		return "apkovl"
	case oci.MediaTypeSquashfs:
		return "squashfs"
	case oci.MediaTypeCmdline:
		return "cmdline"
	}
	switch title {
	case "vmlinuz", "kernel":
		return "kernel"
	case "initrd", "initramfs":
		return "initrd"
	case "modules":
		return "modules"
	case "modloop", "modloop-virt":
		return "modloop"
	case "apkovl":
		return "apkovl"
	case "squashfs", "filesystem.squashfs":
		return "squashfs"
	case "cmdline":
		return "cmdline"
	}
	return ""
}

// pick returns candidate when non-empty, else cur. The materialize() flow
// accumulates kernel/initrd/modules paths across multiple OCI refs and uses
// pick to prefer a freshly-discovered value over a previously-cached one.
func pick(cur, candidate string) string {
	if candidate != "" {
		return candidate
	}
	return cur
}

// modeOrDefault returns def when v is empty.
func modeOrDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// wrapAsCpioGz packs a single file (srcPath, exposed as dstName) into
// a gzipped newc-cpio archive at outPath. Used to fold the apkovl blob
// into the kexec'd initramfs as `/apkovl.tar.gz`, so Alpine's init
// sees a local file with the `.gz` suffix it expects (its
// `unpack_apkovl` parses `${ovl##*.}` and dispatches accordingly —
// no suffix means the encrypted-overlay branch, which calls `apk add
// openssl` before the repositories file exists). Embedding it
// sidesteps the OCI blob URL's `sha256:…` filename problem entirely.
func wrapAsCpioGz(srcPath, dstName, outPath string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	cw := cpio.NewWriter(gz)
	if err := cw.WriteFile(cpio.Header{Name: dstName, Mode: 0o100000 | 0o644}, data); err != nil {
		return err
	}
	if err := cw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// concat appends each src file's bytes to dst in order. Used to glue a
// modules cpio.gz onto the initrd before kexec — the Linux kernel
// transparently handles a stream of concatenated gzipped cpio archives.
func concat(dst string, srcs ...string) error {
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	for _, s := range srcs {
		in, err := os.Open(s)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, in)
		in.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
