/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"fmt"
	"strconv"
	"strings"
)

// PortRange is an inclusive range of UDP ports [First, Last].
// A single port is the degenerate case First == Last.
type PortRange struct {
	First uint16
	Last  uint16
}

func PortRangeFromPorts(a, b uint16) PortRange {
	if a > b {
		return PortRange{First: b, Last: a}
	}
	return PortRange{First: a, Last: b}
}

// Valid reports whether the range describes at least one legal port.
func (p PortRange) Valid() bool {
	return p.First != 0
}

func (p PortRange) Size() int {
	if !p.Valid() {
		return 0
	}
	return int(p.Last) - int(p.First) + 1
}

func (p PortRange) IsSingle() bool {
	return p.Valid() && p.First == p.Last
}

func (p PortRange) Contains(port uint16) bool {
	return p.Valid() && port >= p.First && port <= p.Last
}

func (p PortRange) String() string {
	if !p.Valid() {
		return "0"
	}
	if p.IsSingle() {
		return strconv.Itoa(int(p.First))
	}
	return fmt.Sprintf("%d-%d", p.First, p.Last)
}

// ParsePortRange parses "port" or "portA-portB" (inclusive).
func ParsePortRange(s string) (PortRange, error) {
	if s == "" {
		return PortRange{}, fmt.Errorf("empty port range")
	}
	first, rest, hasDash := strings.Cut(s, "-")
	lo, err := strconv.ParseUint(first, 10, 16)
	if err != nil {
		return PortRange{}, fmt.Errorf("invalid port range %q: %w", s, err)
	}
	if !hasDash {
		if lo == 0 {
			return PortRange{}, fmt.Errorf("port must be greater than 0")
		}
		return PortRange{First: uint16(lo), Last: uint16(lo)}, nil
	}
	hi, err := strconv.ParseUint(rest, 10, 16)
	if err != nil {
		return PortRange{}, fmt.Errorf("invalid port range %q: %w", s, err)
	}
	if lo == 0 || hi == 0 || lo > hi {
		return PortRange{}, fmt.Errorf("invalid port range %q: must be 1-65535 with first <= last", s)
	}
	return PortRange{First: uint16(lo), Last: uint16(hi)}, nil
}

// RangeOpener is implemented by binds that can listen on a whole port range
// in addition to their primary port (server half of port hopping).
type RangeOpener interface {
	// OpenRange binds every port in r except port (already bound as the
	// primary) and returns additional receive functions for them. It must be
	// called after a successful Open.
	OpenRange(port uint16, r PortRange) ([]ReceiveFunc, error)
}
