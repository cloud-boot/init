//go:build !linux

package netconf

import "errors"

type Config struct{}

func Setup(_ string) (*Config, error) { return nil, errors.New("netconf: linux-only") }
