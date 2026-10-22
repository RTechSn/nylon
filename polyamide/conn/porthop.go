/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"errors"
	"sync"
)

// PortHopBind wraps any Bind and adds destination port-range support on the
// send path. It is the client half of port hopping: a peer endpoint parsed
// from "ip:portA-portB" becomes a *RangeEndpoint whose embedded hop controller
// rotates the destination port once the per-port packet budget is exhausted.
//
// Everything else — listening, marks, receiving — is delegated to the inner
// bind unchanged. With no range endpoints in use, PortHopBind is behaviourally
// identical to the inner bind.
type PortHopBind struct {
	mu    sync.RWMutex
	inner Bind
	cfg   HopConfig
}

var (
	_ Bind            = (*PortHopBind)(nil)
	_ HopConfigSetter = (*PortHopBind)(nil)
	_ HopConfigGetter = (*PortHopBind)(nil)
	_ RangeOpener     = (*PortHopBind)(nil)
)

// HopConfigSetter is implemented by binds whose client-side rotation policy
// can be reconfigured at runtime.
type HopConfigSetter interface {
	SetHopConfig(cfg HopConfig)
}

// HopConfigGetter is implemented by binds that expose their current
// client-side rotation policy.
type HopConfigGetter interface {
	HopConfig() HopConfig
}

// RangeOpener is implemented by binds that can listen on a whole port range
// in addition to their primary port (server half of port hopping).
type RangeOpener interface {
	// OpenRange binds every port in r except port (already bound as the
	// primary) and returns additional receive functions for them. It must be
	// called after a successful Open.
	OpenRange(port uint16, r PortRange) ([]ReceiveFunc, error)
}

func NewPortHopBind(inner Bind, cfg HopConfig) *PortHopBind {
	if inner == nil {
		panic("PortHopBind: nil inner bind")
	}
	return &PortHopBind{inner: inner, cfg: cfg}
}

func (b *PortHopBind) Inner() Bind { return b.inner }

func (b *PortHopBind) HopConfig() HopConfig {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.cfg
}

func (b *PortHopBind) SetHopConfig(cfg HopConfig) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cfg = cfg
}

func (b *PortHopBind) ParseEndpoint(s string) (Endpoint, error) {
	addr, r, isRange, err := parseRangeEndpointString(s)
	if err != nil {
		return nil, err
	}
	if isRange {
		return NewRangeEndpoint(b.inner, addr, r, b.HopConfig()), nil
	}
	return b.inner.ParseEndpoint(s)
}

func (b *PortHopBind) Send(bufs [][]byte, ep Endpoint) error {
	switch e := ep.(type) {
	case *RangeEndpoint:
		return e.SendThrough(b.inner, bufs)
	case countedParent:
		// Fixed-port view of a range endpoint (a connection attempt):
		// send through the inner endpoint, then account the packets against
		// the rotation budget.
		err := b.inner.Send(bufs, e.countedEndpoint())
		e.countPackets(len(bufs))
		return err
	default:
		return b.inner.Send(bufs, ep)
	}
}

func (b *PortHopBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	return b.inner.Open(port)
}

func (b *PortHopBind) Close() error { return b.inner.Close() }

func (b *PortHopBind) SetMark(mark uint32) error { return b.inner.SetMark(mark) }

func (b *PortHopBind) BatchSize() int { return b.inner.BatchSize() }

func (b *PortHopBind) OpenRange(port uint16, r PortRange) ([]ReceiveFunc, error) {
	if ro, ok := b.inner.(RangeOpener); ok {
		return ro.OpenRange(port, r)
	}
	return nil, errors.New("inner bind does not support listen ranges")
}

// SendThrough assigns a destination port to every buffer (rotating at budget
// boundaries) and sends each contiguous same-port run through bind.
func (e *RangeEndpoint) SendThrough(bind Bind, bufs [][]byte) error {
	if len(bufs) == 0 {
		return nil
	}
	e.mu.Lock()
	if len(e.scratch) < len(bufs) {
		e.scratch = make([]uint16, len(bufs))
	}
	ports := e.scratch[:len(bufs)]
	e.assignPortsLocked(ports)
	// Materialize per-port endpoints under the same lock so that runs and
	// counters stay consistent. A run covers [run.start, run.end).
	type run struct {
		start, end int
		ep         Endpoint
	}
	runs := make([]run, 0, 4)
	start := 0
	for i := 1; i <= len(bufs); i++ {
		if i == len(bufs) || ports[i] != ports[start] {
			runs = append(runs, run{start, i, e.endpointFor(ports[start])})
			start = i
		}
	}
	e.mu.Unlock()

	var firstErr error
	for _, r := range runs {
		if err := bind.Send(bufs[r.start:r.end], r.ep); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
