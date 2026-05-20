package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// pickNewestFile returns the most-recently-modified file matching glob.
// Returns an empty string and an error if no file matches.
//
// Pulled out of disk_linux.go so it can be unit-tested on any OS.
func pickNewestFile(glob string) (string, error) {
	matches, err := filepath.Glob(glob)
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no files match %s", glob)
	}
	sort.Slice(matches, func(i, j int) bool {
		ai, _ := os.Stat(matches[i])
		aj, _ := os.Stat(matches[j])
		return ai.ModTime().After(aj.ModTime())
	})
	return matches[0], nil
}

// pairInitrdWithKernel takes the path of a kernel image like
//
//	/mnt/boot/vmlinuz-6.6.0-1-amd64
//
// and looks for the matching initrd alongside it. Tries the three
// naming conventions that cover Debian/Ubuntu (`initrd.img-X`),
// Fedora/RHEL (`initramfs-X.img`) and Arch / openSUSE (`initrd-X`).
//
// `exists` is the predicate used to probe the filesystem; production
// callers pass os.Stat-style, tests pass a synthetic map. The split
// lets us unit-test the naming logic without touching disk.
func pairInitrdWithKernel(kernelPath string, exists func(string) bool) (string, error) {
	dir := filepath.Dir(kernelPath)
	base := filepath.Base(kernelPath)
	// Strip whichever prefix the kernel filename starts with — vmlinuz-
	// or Image- (openSUSE arm64). Anything else is a naming convention
	// we don't yet handle; return an error so the caller falls back
	// to an explicit Disk.Initrd override.
	var suffix string
	switch {
	case strings.HasPrefix(base, "vmlinuz-"):
		suffix = strings.TrimPrefix(base, "vmlinuz-")
	case strings.HasPrefix(base, "Image-"):
		suffix = strings.TrimPrefix(base, "Image-")
	default:
		return "", fmt.Errorf("kernel %s matches neither vmlinuz-* nor Image-* convention", kernelPath)
	}
	candidates := []string{
		filepath.Join(dir, "initrd.img-"+suffix),
		filepath.Join(dir, "initramfs-"+suffix+".img"),
		filepath.Join(dir, "initrd-"+suffix),
	}
	for _, p := range candidates {
		if exists(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("no initrd next to %s (tried %v)", kernelPath, candidates)
}
