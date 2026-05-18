//go:build !linux

package lldp

import (
	"errors"
	"time"
)

func Listen(_ string, _ time.Duration) (*Facts, error) {
	return nil, errors.New("lldp: linux-only")
}

func Send(_, _, _ string) error { return errors.New("lldp: linux-only") }
