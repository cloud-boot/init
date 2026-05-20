//go:build linux

package main

import (
	"encoding/binary"
	"testing"
)

// TestEncodeLoadOption verifies the byte layout against UEFI 2.10
// §3.1.3 for a representative input. The encoded LoadOption goes
// straight into /sys/firmware/efi/efivars/Boot0001-… (prefixed by
// efivarfs's 4-byte attributes header that writeEFIVar adds).
func TestEncodeLoadOption(t *testing.T) {
	desc := "cloud-boot debian"
	fp := `\EFI\Linux\debian-vmlinuz.efi`
	cmdline := `initrd=\EFI\Linux\debian-initrd console=hvc0 ro`

	out := encodeLoadOption(desc, fp, cmdline)
	if len(out) < 6 {
		t.Fatalf("encoded too short: %d bytes", len(out))
	}

	// Attributes must be LOAD_OPTION_ACTIVE (0x01).
	if got := binary.LittleEndian.Uint32(out[0:4]); got != 0x01 {
		t.Errorf("attributes = 0x%x, want 0x01", got)
	}
	// FilePathListLength must equal len(FILE_PATH node) +
	// len(END node = 4). Compute the expected node size:
	// header 4 + (len(fp)+1)*2 bytes of UTF-16LE+NUL.
	wantFPNode := 4 + (len(fp)+1)*2
	wantFPList := uint16(wantFPNode + 4)
	if got := binary.LittleEndian.Uint16(out[4:6]); got != wantFPList {
		t.Errorf("FilePathListLength = %d, want %d", got, wantFPList)
	}

	// Description follows at offset 6, UTF-16LE NUL-terminated.
	// Decode it back and compare.
	descStart := 6
	descBytes := (len(desc) + 1) * 2 // chars + NUL
	got := decodeUTF16LE(t, out[descStart:descStart+descBytes])
	if got != desc {
		t.Errorf("description = %q, want %q", got, desc)
	}

	// FilePathList follows. First node must be MEDIA_FILEPATH
	// (type=0x04, subtype=0x04).
	fpStart := descStart + descBytes
	if out[fpStart] != 0x04 || out[fpStart+1] != 0x04 {
		t.Errorf("file-path node type/subtype = %d/%d, want 4/4",
			out[fpStart], out[fpStart+1])
	}
	nodeLen := binary.LittleEndian.Uint16(out[fpStart+2 : fpStart+4])
	if int(nodeLen) != wantFPNode {
		t.Errorf("file-path node length = %d, want %d", nodeLen, wantFPNode)
	}
	gotPath := decodeUTF16LE(t, out[fpStart+4:fpStart+int(nodeLen)])
	if gotPath != fp {
		t.Errorf("file path = %q, want %q", gotPath, fp)
	}

	// END node next: 7F FF 04 00.
	endStart := fpStart + int(nodeLen)
	if out[endStart] != 0x7F || out[endStart+1] != 0xFF ||
		out[endStart+2] != 0x04 || out[endStart+3] != 0x00 {
		t.Errorf("END node mismatch: %x", out[endStart:endStart+4])
	}

	// OptionalData = cmdline as UTF-16LE.
	cmdStart := endStart + 4
	gotCmd := decodeUTF16LE(t, out[cmdStart:])
	if gotCmd != cmdline {
		t.Errorf("optionalData = %q, want %q", gotCmd, cmdline)
	}
}

// TestEncodeLoadOption_NoCmdline checks the no-OptionalData path —
// targets without an initrd or a cmdline shouldn't emit a stray
// 2-byte NUL after the END device-path node.
func TestEncodeLoadOption_NoCmdline(t *testing.T) {
	out := encodeLoadOption("d", `\foo.efi`, "")
	// The structure should end right at the END node — no
	// trailing optionalData bytes.
	if got := out[len(out)-4:]; got[0] != 0x7F || got[1] != 0xFF {
		t.Errorf("expected END node at tail, got %x", got)
	}
}

// decodeUTF16LE pulls a UTF-16LE NUL-terminated string out of the
// supplied bytes. Mirrors the layout encodeLoadOption emits.
func decodeUTF16LE(t *testing.T, b []byte) string {
	t.Helper()
	var out []rune
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		out = append(out, rune(c))
	}
	return string(out)
}
