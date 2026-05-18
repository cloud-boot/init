//go:build !linux

package lldp

import "testing"

func TestStubsReturnError(t *testing.T) {
	if _, err := Listen("any", 0); err == nil {
		t.Error("Listen should error on non-linux")
	}
	if err := Send("any", "n", "d"); err == nil {
		t.Error("Send should error on non-linux")
	}
}
