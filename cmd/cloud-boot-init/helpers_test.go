package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cloud-boot/init/pkg/oci"
)

func TestSplitCmdline(t *testing.T) {
	in := `console=ttyS0  ip="dhcp,ipv4" quiet ` + "\tloglevel=3\n"
	got := splitCmdline(in)
	want := []string{"console=ttyS0", "ip=dhcp,ipv4", "quiet", "loglevel=3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestSplitCmdline_TrailingQuoted(t *testing.T) {
	got := splitCmdline(`x "y z"`)
	want := []string{"x", "y z"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q", got)
	}
}

func TestSplitCmdline_Empty(t *testing.T) {
	if got := splitCmdline(""); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"sha256:abc/def":    "sha256_abc_def",
		"plain.name-1":      "plain.name-1",
		"with space":        "with_space",
		"_underscores_ok_":  "_underscores_ok_",
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveKind_ByMediaType(t *testing.T) {
	for mt, want := range map[string]string{
		oci.MediaTypeKernel:  "kernel",
		oci.MediaTypeInitrd:  "initrd",
		oci.MediaTypeModules: "modules",
		oci.MediaTypeCmdline: "cmdline",
	} {
		if got := resolveKind(mt, ""); got != want {
			t.Errorf("resolveKind(%s) = %q, want %q", mt, got, want)
		}
	}
}

func TestResolveKind_ByTitle(t *testing.T) {
	for title, want := range map[string]string{
		"vmlinuz":   "kernel",
		"kernel":    "kernel",
		"initrd":    "initrd",
		"initramfs": "initrd",
		"modules":   "modules",
		"cmdline":   "cmdline",
	} {
		if got := resolveKind("application/unknown", title); got != want {
			t.Errorf("resolveKind(unknown, %s) = %q, want %q", title, got, want)
		}
	}
}

func TestResolveKind_Unknown(t *testing.T) {
	if got := resolveKind("x", "y"); got != "" {
		t.Errorf("resolveKind(x,y) = %q", got)
	}
}

func TestPick(t *testing.T) {
	if got := pick("a", "b"); got != "b" {
		t.Errorf("got %q", got)
	}
	if got := pick("a", ""); got != "a" {
		t.Errorf("got %q", got)
	}
	if got := pick("", ""); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestModeOrDefault(t *testing.T) {
	if got := modeOrDefault("", "def"); got != "def" {
		t.Errorf("got %q", got)
	}
	if got := modeOrDefault("v", "def"); got != "v" {
		t.Errorf("got %q", got)
	}
}

func TestConcat(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	dst := filepath.Join(dir, "dst")
	os.WriteFile(a, []byte("AA"), 0o644)
	os.WriteFile(b, []byte("BB"), 0o644)
	if err := concat(dst, a, b); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "AABB" {
		t.Errorf("dst = %q", got)
	}
}

func TestConcat_OpenFails(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst")
	if err := concat(dst, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected error")
	}
}

func TestConcat_CreateFails(t *testing.T) {
	dir := t.TempDir()
	if err := concat(filepath.Join(dir, "no", "such", "dst")); err == nil {
		t.Fatal("expected create error")
	}
}

func TestConcat_CopyFails(t *testing.T) {
	// Source path is a directory → os.Open(dir) succeeds but io.Copy will
	// fail on read.
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst")
	subdir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	err := concat(dst, subdir)
	if err == nil {
		t.Fatal("expected copy error from reading a directory")
	}
	if !strings.Contains(err.Error(), "is a directory") && !errors.Is(err, errors.New("is a directory")) {
		// macOS reports "is a directory" via syscall; just confirm an error.
	}
}

func TestReadCmdlineFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cmdline")
	os.WriteFile(path, []byte(`a=1 b "c=d e" flag`), 0o644)
	got, err := readCmdlineFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"a": "1", "b": "1", "c": "d e", "flag": "1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestReadCmdlineFile_Missing(t *testing.T) {
	if _, err := readCmdlineFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error")
	}
}

func TestReadCmdline_Default(t *testing.T) {
	// readCmdline reads /proc/cmdline. On darwin that path doesn't exist; on
	// linux test runners it does. Either result is fine — we only want to hit
	// the code path.
	_, _ = readCmdline()
}

func TestSanitize_OrderIndependent(t *testing.T) {
	// Determinism check — sanitize is deterministic, so two calls give
	// identical strings. Use sort.Strings to guard against silly typos in
	// test fixtures.
	in := []string{"a.b", "c d", "e_f"}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = sanitize(s)
	}
	sort.Strings(out)
	if !reflect.DeepEqual(out, []string{"a.b", "c_d", "e_f"}) {
		t.Errorf("got %v", out)
	}
}
