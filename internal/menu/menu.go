// Package menu renders the interactive boot-time chooser shown by
// cloud-boot-init before kexec. The menu lists every eligible plan target,
// prints a countdown, and reads a single line from the console. On timeout
// or empty input the default target wins.
//
// Input grammar is deliberately tiny so the operator can pick a target with
// minimal typing on a serial console:
//
//	<empty>          → default
//	<number>         → 1-based index into the displayed options
//	<name>           → exact match against Target.Name (case-insensitive)
//	<name prefix>    → unambiguous prefix match against Target.Name
//
// The menu does NOT manipulate the terminal mode (no raw / no-echo): line
// buffering plus Enter is good enough for an initramfs console, costs no
// portability surface, and lets the operator correct a typo with backspace.
package menu

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Option is one row shown to the operator. Name is the canonical identifier
// returned to the caller; Label is the optional pretty form used for display
// (falls back to Name when empty).
type Option struct {
	Name  string
	Label string
}

// Config bundles the runtime knobs of a single Prompt call. Out is where the
// header/countdown/options are written; In is where the operator's line is
// read. Timeout zero disables the auto-select branch and waits forever.
type Config struct {
	Out      io.Writer
	In       io.Reader
	Prompt   string        // header line; defaults to "Select a boot target:"
	Timeout  time.Duration // wall-clock budget before auto-selecting default
	Default  string        // Option.Name returned on timeout/empty input
	Options  []Option
	progress io.Writer // overridden in tests; nil means "use Out"
}

// Prompt renders the menu and blocks until the operator picks an option or
// the timeout fires. The returned string is one of the Option.Name values.
//
// Errors are reserved for "I/O on Out failed" — bad operator input loops back
// to the prompt rather than aborting the boot.
func Prompt(cfg Config) (string, error) {
	if len(cfg.Options) == 0 {
		return "", fmt.Errorf("menu: no options")
	}
	if cfg.Prompt == "" {
		cfg.Prompt = "Select a boot target:"
	}
	defIdx := indexByName(cfg.Options, cfg.Default)
	if defIdx < 0 {
		defIdx = 0
		cfg.Default = cfg.Options[0].Name
	}
	if err := writeHeader(cfg.Out, cfg.Prompt, cfg.Options, defIdx); err != nil {
		return "", err
	}

	// One scanner shared across retries — creating a new bufio.Scanner per
	// line would drop bytes the previous scanner had already buffered past
	// the newline.
	scanner := bufio.NewScanner(cfg.In)

	// readNext fires the next line read in its own goroutine so waitForLine
	// can race it against the countdown. The goroutine leaks if we hit the
	// timeout, but cloud-boot-init kexecs immediately after this call so
	// the leak is bounded by the lifetime of PID 1.
	readNext := func() <-chan string {
		ch := make(chan string, 1)
		go func() {
			if scanner.Scan() {
				ch <- scanner.Text()
				return
			}
			ch <- ""
		}()
		return ch
	}

	readCh := readNext()
	for {
		line, timedOut, err := waitForLine(cfg, readCh)
		if err != nil {
			return "", err
		}
		if timedOut {
			fmt.Fprintf(cfg.Out, "\ntimeout: booting %q\n", cfg.Default)
			return cfg.Default, nil
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return cfg.Default, nil
		}
		if name, ok := resolveChoice(line, cfg.Options); ok {
			return name, nil
		}
		fmt.Fprintf(cfg.Out, "unknown choice %q; try again or wait for default %q\n",
			line, cfg.Default)
		// On a retry abandon the countdown — the operator is clearly at
		// the keyboard. Subsequent reads block on the shared scanner.
		readCh = readNext()
		cfg.Timeout = 0
	}
}

// waitForLine multiplexes the operator's input against the countdown. With
// Timeout == 0 it blocks on readCh forever. With Timeout > 0 it prints a
// one-line countdown on the progress writer and races the input.
func waitForLine(cfg Config, readCh <-chan string) (line string, timedOut bool, err error) {
	if cfg.Timeout <= 0 {
		fmt.Fprintf(cfg.Out, "choice [%s]: ", cfg.Default)
		return <-readCh, false, nil
	}
	prog := cfg.progress
	if prog == nil {
		prog = cfg.Out
	}
	deadline := time.Now().Add(cfg.Timeout)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	// Initial render so the operator sees the countdown immediately.
	remaining := cfg.Timeout
	fmt.Fprintf(prog, "\rbooting %q in %ds — type a choice + Enter to override: ",
		cfg.Default, secondsCeil(remaining))
	for {
		select {
		case s := <-readCh:
			fmt.Fprintln(prog)
			return s, false, nil
		case <-tick.C:
			remaining = time.Until(deadline)
			if remaining <= 0 {
				return "", true, nil
			}
			fmt.Fprintf(prog, "\rbooting %q in %ds — type a choice + Enter to override: ",
				cfg.Default, secondsCeil(remaining))
		}
	}
}

func writeHeader(w io.Writer, prompt string, opts []Option, defIdx int) error {
	if _, err := fmt.Fprintln(w, prompt); err != nil {
		return err
	}
	for i, o := range opts {
		marker := " "
		if i == defIdx {
			marker = "*"
		}
		label := o.Label
		if label == "" {
			label = o.Name
		}
		if _, err := fmt.Fprintf(w, " %s %d) %s (%s)\n", marker, i+1, label, o.Name); err != nil {
			return err
		}
	}
	return nil
}

// resolveChoice maps an operator line to an Option.Name. Numeric input is a
// 1-based index; alphabetic input matches case-insensitively, exact first,
// then unambiguous prefix. Returns ok=false when nothing fits.
func resolveChoice(line string, opts []Option) (string, bool) {
	if n, err := strconv.Atoi(line); err == nil {
		if n >= 1 && n <= len(opts) {
			return opts[n-1].Name, true
		}
		return "", false
	}
	low := strings.ToLower(line)
	for _, o := range opts {
		if strings.EqualFold(o.Name, line) {
			return o.Name, true
		}
	}
	var match string
	var hits int
	for _, o := range opts {
		if strings.HasPrefix(strings.ToLower(o.Name), low) {
			match = o.Name
			hits++
		}
	}
	if hits == 1 {
		return match, true
	}
	return "", false
}

func indexByName(opts []Option, name string) int {
	for i, o := range opts {
		if o.Name == name {
			return i
		}
	}
	return -1
}

// secondsCeil rounds up to the nearest second so the countdown reads "5"
// for the whole final second rather than flashing to 0 too early.
func secondsCeil(d time.Duration) int {
	s := int(d / time.Second)
	if d%time.Second > 0 {
		s++
	}
	return s
}
