package cpio

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"testing"
)

type parsed struct {
	Name   string
	Mode   uint32
	Size   uint32
	RMajor uint32
	RMinor uint32
	Data   []byte
}

func parseNewc(t *testing.T, buf []byte) []parsed {
	t.Helper()
	var out []parsed
	for i := 0; i+110 <= len(buf); {
		if string(buf[i:i+6]) != magic {
			t.Fatalf("bad magic at offset %d: %q", i, buf[i:i+6])
		}
		field := func(off int) uint32 {
			v, err := strconv.ParseUint(string(buf[i+off:i+off+8]), 16, 32)
			if err != nil {
				t.Fatalf("hex field at %d: %v", off, err)
			}
			return uint32(v)
		}
		mode := field(14)
		size := field(54)
		rmaj := field(78)
		rmin := field(86)
		namesize := field(94)

		nameStart := i + 110
		name := string(buf[nameStart : nameStart+int(namesize)-1])
		i = nameStart + int(namesize)
		if r := i % 4; r != 0 {
			i += 4 - r
		}
		dataStart := i
		i += int(size)
		if r := i % 4; r != 0 {
			i += 4 - r
		}
		out = append(out, parsed{
			Name:   name,
			Mode:   mode,
			Size:   size,
			RMajor: rmaj,
			RMinor: rmin,
			Data:   append([]byte(nil), buf[dataStart:dataStart+int(size)]...),
		})
		if name == trailer {
			break
		}
	}
	return out
}

func TestWriter_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.WriteDir("etc", 0o755))
	must(w.WriteFile(Header{Name: "etc/hello", Mode: 0o100644, Uid: 1, Gid: 2, Mtim: 0xDEAD}, []byte("hi")))
	must(w.WriteSymlink("etc/link", "hello", 0o777))
	must(w.WriteNod("dev/null", 0o020666, 1, 3))
	must(w.Close())

	entries := parseNewc(t, buf.Bytes())
	got := map[string]parsed{}
	for _, e := range entries {
		got[e.Name] = e
	}
	if _, ok := got[trailer]; !ok {
		t.Fatal("missing TRAILER!!!")
	}
	if e := got["etc"]; e.Mode != 0o040755 {
		t.Errorf("dir mode = %o, want %o", e.Mode, 0o040755)
	}
	if e := got["etc/hello"]; e.Mode != 0o100644 || string(e.Data) != "hi" {
		t.Errorf("file entry = %+v", e)
	}
	if e := got["etc/link"]; e.Mode != 0o120777 || string(e.Data) != "hello" {
		t.Errorf("symlink entry = %+v", e)
	}
	if e := got["dev/null"]; e.Mode != 0o020666 || e.RMajor != 1 || e.RMinor != 3 {
		t.Errorf("nod entry = %+v", e)
	}
	if len(buf.Bytes())%512 != 0 {
		t.Errorf("archive length = %d, not a multiple of 512", len(buf.Bytes()))
	}
}

// limitWriter accepts at most n bytes then returns an error on subsequent
// writes. Used to exercise each error-return path in the writer state machine.
type limitWriter struct{ n int }

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("boom")
	}
	if len(p) <= l.n {
		l.n -= len(p)
		return len(p), nil
	}
	k := l.n
	l.n = 0
	return k, errors.New("boom")
}

// TestWriter_HeaderErrors covers each return-on-error branch inside
// writeHeaderFull (header, name, NUL, internal pad4).
func TestWriter_HeaderErrors(t *testing.T) {
	// Each subtest pairs a (limit, name) with a description.
	cases := []struct {
		name  string
		entry string
		limit int
	}{
		{"hdr-fail", "x", 0},
		{"name-fail", "x", 110},
		{"nul-fail", "x", 111},
		{"pad4-fail", "xx", 113}, // 110+2+1 written, pad4 starts then fails
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := NewWriter(&limitWriter{n: c.limit})
			err := w.WriteFile(Header{Name: c.entry, Mode: 0o100644}, nil)
			if err == nil {
				t.Fatalf("limit=%d: expected error", c.limit)
			}
		})
	}
}

// TestWriter_BodyErrors covers each return-on-error branch inside writeBody.
func TestWriter_BodyErrors(t *testing.T) {
	// For Name="x", a successful header consumes 112 bytes (110+1+1, pad=0).
	cases := []struct {
		name  string
		limit int
	}{
		{"body-write-fail", 112}, // header succeeds, body write fails
		{"body-pad4-fail", 114},  // header+body OK (data=2), pad4 fails
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := NewWriter(&limitWriter{n: c.limit})
			err := w.WriteFile(Header{Name: "x", Mode: 0o100644}, []byte("hi"))
			if err == nil {
				t.Fatalf("limit=%d: expected error", c.limit)
			}
		})
	}
}

// TestWriter_CloseTrailerError covers the trailer-write error path.
func TestWriter_CloseTrailerError(t *testing.T) {
	w := NewWriter(&limitWriter{n: 0})
	if err := w.Close(); err == nil {
		t.Fatal("expected trailer error")
	}
}

// TestWriter_ClosePadAlreadyZero exercises the no-pad branch of Close: the
// trailer entry is 124 bytes, so pre-seeding pos=388 lands us exactly on a
// 512-byte boundary after the trailer is written.
func TestWriter_ClosePadAlreadyZero(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	w.pos = 388
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 124 {
		t.Errorf("expected only the trailer (124 B), got %d", buf.Len())
	}
}

// TestWriter_ClosePadWriteError fails the final 512-byte pad write of Close.
func TestWriter_ClosePadWriteError(t *testing.T) {
	// Close emits trailer (124 bytes) then pad to 512 = 388 bytes. Allow
	// exactly the trailer through; the pad write should fail.
	w := NewWriter(&limitWriter{n: 124})
	if err := w.Close(); err == nil {
		t.Fatal("expected pad error")
	}
}

func TestWriter_EmptyDataAndIno(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	for i := 0; i < 3; i++ {
		if err := w.WriteFile(Header{Name: fmt.Sprintf("f%d", i), Mode: 0o100644}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	entries := parseNewc(t, buf.Bytes())
	if len(entries) != 4 {
		t.Fatalf("len(entries) = %d, want 4", len(entries))
	}
}

func TestWriter_Pad4NoOp(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	w.pos = 4
	if err := w.pad4(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("pad4 wrote %d bytes when alignment is 0", buf.Len())
	}
}

// TestWriter_SymlinkHeaderError fans out coverage to WriteSymlink's error
// path on its first cw.writeHeader call.
func TestWriter_SymlinkHeaderError(t *testing.T) {
	w := NewWriter(&limitWriter{n: 0})
	if err := w.WriteSymlink("l", "t", 0o777); err == nil {
		t.Fatal("expected error")
	}
}

func TestParserSelfCheck(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	_ = w.WriteFile(Header{Name: "x", Mode: 0o100644}, []byte("y"))
	_ = w.Close()
	entries := parseNewc(t, buf.Bytes())
	if len(entries) < 2 || entries[1].Name != trailer {
		raw := hex.EncodeToString(buf.Bytes())
		t.Fatalf("unexpected parse: %v\nbytes=%s", entries, raw)
	}
}
