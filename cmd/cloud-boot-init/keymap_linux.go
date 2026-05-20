//go:build linux

// Keymap loader for the menu UI.
//
// The kernel ships with a hard-coded US-QWERTY keymap; runtime
// switching is done via the KDSKBENT ioctl on a /dev/tty* fd
// (the same mechanism that userspace `loadkeys` uses). Each call
// writes one (table, keycode, keysym) triple — to load a full
// layout we replay the diff against the kernel default for every
// keycode we want to override.
//
// Scope: this is "type the boot menu choice in your native
// layout", not full keymap fidelity. We embed minimal tables
// for the layouts cloud-boot users have asked for (currently
// just "fr"); shipping busybox + the kbd package + the
// 200 KB of /usr/share/keymaps would be a much bigger lift
// for a benefit that disappears the moment the user picks a
// target (after which the staged distro kernel owns the
// keymap anyway).
//
// Cmdline knob:
//   cloudboot.keymap=fr      # French AZERTY (PC layout)
//   cloudboot.keymap=fr-mac  # French AZERTY (Apple MacBook layout)
//   cloudboot.keymap=us      # noop (kernel default)
//   cloudboot.keymap=        # noop
//
// Adding more layouts: declare another []keymapEntry table and
// add a case to the switch in loadKeymap.

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// KDSKBENT — ioctl request number for "set keyboard entry".
// Defined in linux/kd.h as the legacy literal 0x4B47 (not _IOC-
// encoded; the kbd API predates the encoding scheme).
const ioctlKDSKBENT = 0x4B47

// kbentry mirrors struct kbentry from <linux/kd.h>. Size = 4
// bytes, no internal padding because uint16 is 2-byte aligned
// and lands cleanly at offset 2.
type kbentry struct {
	KbTable byte
	KbIndex byte
	KbValue uint16
}

// keymapEntry: one keycode, four table slots (plain, shift,
// altgr, shift+altgr). 0 means "don't override the kernel
// default for that table" — handy when a key only differs in
// the unshifted slot.
type keymapEntry struct {
	keycode uint16
	values  [4]uint16
}

// frAzerty is a minimal French AZERTY override of the kernel's
// US-QWERTY default. Only the keys that move or change symbol
// are listed; everything else (Enter, Space, Esc, modifiers,
// most punctuation that matches US) keeps the kernel default.
//
// Non-ASCII values are Latin-1 codepoints; the framebuffer
// console under our cloud kernel uses a Latin-1 font (default
// VGA8x16) which renders them correctly. For the menu use case
// (digits + Enter) only the ASCII subset matters anyway — these
// accents are wired up so the user isn't surprised when typing
// other chars after picking a target.
var frAzerty = []keymapEntry{
	// Digit row: physical 1..0,-,= → French &é"'(-è_çà)= (plain);
	// shift gives the actual digits + ° + +.
	{2, [4]uint16{'&', '1', 0, 0}},
	{3, [4]uint16{0xe9 /*é*/, '2', '~', 0}},
	{4, [4]uint16{'"', '3', '#', 0}},
	{5, [4]uint16{'\'', '4', '{', 0}},
	{6, [4]uint16{'(', '5', '[', 0}},
	{7, [4]uint16{'-', '6', '|', 0}},
	{8, [4]uint16{0xe8 /*è*/, '7', '`', 0}},
	{9, [4]uint16{'_', '8', '\\', 0}},
	{10, [4]uint16{0xe7 /*ç*/, '9', '^', 0}},
	{11, [4]uint16{0xe0 /*à*/, '0', '@', 0}},
	{12, [4]uint16{')', 0xb0 /*°*/, ']', 0}},
	{13, [4]uint16{'=', '+', '}', 0}},
	// Top letter row: QWER → AZER (first two swap, rest same).
	{16, [4]uint16{'a', 'A', 0, 0}}, // KEY_Q → a
	{17, [4]uint16{'z', 'Z', 0, 0}}, // KEY_W → z
	// Home row: A → Q.
	{30, [4]uint16{'q', 'Q', 0, 0}}, // KEY_A → q
	// Bottom letter row: Z → W; M shifts to the right of L
	// (where US has the ; key).
	{44, [4]uint16{'w', 'W', 0, 0}}, // KEY_Z → w
	{39, [4]uint16{'m', 'M', 0, 0}}, // KEY_SEMICOLON → m
	// , . / shift one slot left under AZERTY.
	{50, [4]uint16{',', '?', 0, 0}},                  // KEY_M → ,
	{51, [4]uint16{';', '.', 0, 0}},                  // KEY_COMMA → ;
	{52, [4]uint16{':', '/', 0, 0}},                  // KEY_DOT → :
	{53, [4]uint16{'!', 0xa7 /*§*/, 0, 0}},           // KEY_SLASH → !
	{40, [4]uint16{0xf9 /*ù*/, '%', 0, 0}},           // KEY_APOSTROPHE
	{41, [4]uint16{0xb2 /*²*/, 0, 0, 0}},             // KEY_GRAVE
	{26, [4]uint16{'^', 0xa8 /*¨*/, 0, 0}},           // KEY_LEFTBRACE
	{27, [4]uint16{'$', 0xa3 /*£*/, 0, 0}},           // KEY_RIGHTBRACE
	{43, [4]uint16{'*', 0xb5 /*µ*/, 0, 0}},           // KEY_BACKSLASH
}

// frMacAzerty is the Apple MacBook French AZERTY layout — the
// physical labels on a French Apple keyboard differ from the
// PC AZERTY norm on several keys (notably § on the 6 key, ! on
// the 8 key, @ on the leftmost backtick position, = on the slash
// position, - on the equals position). Apple users coming from
// macOS see the keys labelled this way and will mistype if we
// load the PC `fr` table.
//
// Source: Apple's "French (AZERTY)" input source as shipped with
// macOS 14, cross-referenced against the engraving on a 2024
// MacBook Pro French keyboard. Only differences from the
// kernel's US-QWERTY default are encoded — entries that match
// US (the bulk of the letter row) are skipped.
var frMacAzerty = []keymapEntry{
	// Backtick position: Apple labels it @/# (PC AZERTY has ²/³ here).
	{41, [4]uint16{'@', '#', 0, 0}}, // KEY_GRAVE
	// Digit row — Apple AZERTY: & é " ' ( § è ! ç à ) -
	// shifted gives 1 2 3 4 5 6 7 8 9 0 ° _
	{2, [4]uint16{'&', '1', 0, 0}},
	{3, [4]uint16{0xe9 /*é*/, '2', 0, 0}},
	{4, [4]uint16{'"', '3', 0, 0}},
	{5, [4]uint16{'\'', '4', 0, 0}},
	{6, [4]uint16{'(', '5', 0, 0}},
	{7, [4]uint16{0xa7 /*§*/, '6', 0, 0}},
	{8, [4]uint16{0xe8 /*è*/, '7', 0, 0}},
	{9, [4]uint16{'!', '8', 0, 0}},
	{10, [4]uint16{0xe7 /*ç*/, '9', 0, 0}},
	{11, [4]uint16{0xe0 /*à*/, '0', 0, 0}},
	{12, [4]uint16{')', 0xb0 /*°*/, 0, 0}}, // KEY_MINUS
	{13, [4]uint16{'-', '_', 0, 0}},        // KEY_EQUAL (Apple has - here, PC has =)
	// Top letter row: QWER → AZER swap.
	{16, [4]uint16{'a', 'A', 0, 0}}, // KEY_Q → a
	{17, [4]uint16{'z', 'Z', 0, 0}}, // KEY_W → z
	{26, [4]uint16{'^', 0xa8 /*¨*/, 0, 0}}, // KEY_LEFTBRACE
	{27, [4]uint16{'$', '*', 0, 0}},        // KEY_RIGHTBRACE (Apple has $/*; PC is $/£)
	// Home row: A → Q swap.
	{30, [4]uint16{'q', 'Q', 0, 0}}, // KEY_A → q
	{39, [4]uint16{'m', 'M', 0, 0}}, // KEY_SEMICOLON → m
	{40, [4]uint16{0xf9 /*ù*/, '%', 0, 0}}, // KEY_APOSTROPHE
	{43, [4]uint16{'`', 0xa3 /*£*/, 0, 0}}, // KEY_BACKSLASH (Apple has backtick/pound; PC has */µ)
	// Bottom letter row: Z → W swap, then the punctuation.
	{44, [4]uint16{'w', 'W', 0, 0}}, // KEY_Z → w
	{50, [4]uint16{',', '?', 0, 0}}, // KEY_M → ,
	{51, [4]uint16{';', '.', 0, 0}}, // KEY_COMMA → ;
	{52, [4]uint16{':', '/', 0, 0}}, // KEY_DOT → :
	{53, [4]uint16{'=', '+', 0, 0}}, // KEY_SLASH (Apple has =/+; PC has !/§)
}

// loadKeymap replays a keymapEntry slice as KDSKBENT ioctls on
// /dev/tty0. A name of "" or "us" is a no-op (keep the kernel
// default). Unknown names are an error so the operator catches
// typos at boot rather than silently typing the wrong layout.
func loadKeymap(name string) error {
	var km []keymapEntry
	switch name {
	case "", "us":
		return nil
	case "fr":
		km = frAzerty
	case "fr-mac", "mac-fr":
		km = frMacAzerty
	default:
		return fmt.Errorf("unsupported keymap %q (try: fr, fr-mac, us)", name)
	}
	f, err := os.OpenFile("/dev/tty0", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /dev/tty0 for keymap: %w", err)
	}
	defer f.Close()
	for _, e := range km {
		for table := 0; table < len(e.values); table++ {
			if e.values[table] == 0 {
				continue
			}
			kbe := kbentry{
				KbTable: byte(table),
				KbIndex: byte(e.keycode),
				KbValue: e.values[table],
			}
			_, _, errno := syscall.Syscall(
				syscall.SYS_IOCTL,
				f.Fd(),
				uintptr(ioctlKDSKBENT),
				uintptr(unsafe.Pointer(&kbe)),
			)
			if errno != 0 {
				return fmt.Errorf("KDSKBENT keycode=%d table=%d: %w",
					e.keycode, table, errno)
			}
		}
	}
	return nil
}
