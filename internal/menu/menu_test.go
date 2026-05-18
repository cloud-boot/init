package menu

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

var sample = []Option{
	{Name: "primary", Label: "Production"},
	{Name: "rescue", Label: "Rescue shell"},
	{Name: "arm-edge", Label: "ARM edge"},
}

func TestPrompt_DefaultOnEmpty(t *testing.T) {
	var out bytes.Buffer
	got, err := Prompt(Config{
		Out:     &out,
		In:      strings.NewReader("\n"),
		Default: "rescue",
		Options: sample,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "rescue" {
		t.Errorf("got %q, want rescue", got)
	}
	if !strings.Contains(out.String(), "rescue") {
		t.Errorf("menu output missing options: %q", out.String())
	}
}

func TestPrompt_NumericChoice(t *testing.T) {
	got, err := Prompt(Config{
		Out:     io.Discard,
		In:      strings.NewReader("2\n"),
		Default: "primary",
		Options: sample,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "rescue" {
		t.Errorf("got %q", got)
	}
}

func TestPrompt_NameChoice(t *testing.T) {
	got, err := Prompt(Config{
		Out:     io.Discard,
		In:      strings.NewReader("RESCUE\n"),
		Default: "primary",
		Options: sample,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "rescue" {
		t.Errorf("got %q", got)
	}
}

func TestPrompt_PrefixChoice(t *testing.T) {
	got, err := Prompt(Config{
		Out:     io.Discard,
		In:      strings.NewReader("arm\n"),
		Default: "primary",
		Options: sample,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "arm-edge" {
		t.Errorf("got %q", got)
	}
}

func TestPrompt_BadThenGood(t *testing.T) {
	got, err := Prompt(Config{
		Out:     io.Discard,
		In:      strings.NewReader("nope\nrescue\n"),
		Default: "primary",
		Options: sample,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "rescue" {
		t.Errorf("got %q", got)
	}
}

func TestPrompt_TimeoutSelectsDefault(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	var out bytes.Buffer
	done := make(chan struct {
		got string
		err error
	}, 1)
	go func() {
		g, e := Prompt(Config{
			Out:     &out,
			In:      r,
			Default: "primary",
			Timeout: 50 * time.Millisecond,
			Options: sample,
		})
		done <- struct {
			got string
			err error
		}{g, e}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			t.Fatal(res.err)
		}
		if res.got != "primary" {
			t.Errorf("got %q, want primary", res.got)
		}
		if !strings.Contains(out.String(), "timeout") {
			t.Errorf("expected timeout notice, got %q", out.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Prompt did not return after timeout")
	}
}

func TestPrompt_NoOptions(t *testing.T) {
	if _, err := Prompt(Config{Out: io.Discard, In: strings.NewReader("")}); err == nil {
		t.Fatal("expected error with no options")
	}
}

func TestPrompt_BadDefaultFallsBackToFirst(t *testing.T) {
	got, err := Prompt(Config{
		Out:     io.Discard,
		In:      strings.NewReader("\n"),
		Default: "does-not-exist",
		Options: sample,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "primary" {
		t.Errorf("got %q, want primary", got)
	}
}

func TestResolveChoice_Numeric(t *testing.T) {
	if n, ok := resolveChoice("2", sample); !ok || n != "rescue" {
		t.Errorf("got %q,%v", n, ok)
	}
	if _, ok := resolveChoice("99", sample); ok {
		t.Error("99 should not resolve")
	}
}

func TestResolveChoice_AmbiguousPrefix(t *testing.T) {
	opts := []Option{{Name: "rescue"}, {Name: "rescue-2"}}
	if _, ok := resolveChoice("res", opts); ok {
		t.Error("ambiguous prefix should not resolve")
	}
}

func TestSecondsCeil(t *testing.T) {
	cases := map[time.Duration]int{
		0:                       0,
		500 * time.Millisecond:  1,
		1 * time.Second:         1,
		1500 * time.Millisecond: 2,
	}
	for in, want := range cases {
		if got := secondsCeil(in); got != want {
			t.Errorf("secondsCeil(%v) = %d, want %d", in, got, want)
		}
	}
}
