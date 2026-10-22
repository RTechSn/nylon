/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"fmt"
	"sync"
)

// MaxListenRangePorts is the ceiling on the number of extra ports a MultiBind
// will bind in N-socket mode. Every port costs one socket per address family
// (up to 2 file descriptors) and one receive function; wider ranges need the
// netfilter DNAT deployment mode instead (see docs/design/port-hopping.md).
const MaxListenRangePorts = 4096

// MultiBind listens on a primary port (like StdNetBind) plus, optionally, a
// whole range of extra ports — one StdNetBind per port. It is the server half
// of port hopping: a node configured with `listen_ports: a-b` accepts packets
// addressed to any port in the range and, crucially, answers from exactly the
// port the peer's last packet was addressed to (NAT path symmetry).
//
// Receive functions of extra ports produce *TaggedEndpoint values carrying the
// local port; Send routes such endpoints back through the socket that owns
// that port.
type MultiBind struct {
	mu          sync.Mutex
	primary     *StdNetBind
	extras      map[uint16]*StdNetBind
	primaryPort uint16
}

var (
	_ Bind        = (*MultiBind)(nil)
	_ RangeOpener = (*MultiBind)(nil)
)

func NewMultiBind() *MultiBind {
	return &MultiBind{
		primary: NewStdNetBind().(*StdNetBind),
		extras:  make(map[uint16]*StdNetBind),
	}
}

// TaggedEndpoint is a received-packet endpoint annotated with the local
// (listening) port it arrived on, so replies can be routed through the
// correct socket.
type TaggedEndpoint struct {
	Endpoint
	localPort uint16
}

var (
	_ Endpoint                       = (*TaggedEndpoint)(nil)
	_ interface{ PortHint() uint16 } = (*TaggedEndpoint)(nil)
)

// PortHint returns the local port replies to this endpoint must originate
// from.
func (t *TaggedEndpoint) PortHint() uint16 { return t.localPort }

func (b *MultiBind) ParseEndpoint(s string) (Endpoint, error) {
	return b.primary.ParseEndpoint(s)
}

func (b *MultiBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	fns, actual, err := b.primary.Open(port)
	if err == nil {
		b.primaryPort = actual
	}
	return fns, actual, err
}

func (b *MultiBind) OpenRange(port uint16, r PortRange) ([]ReceiveFunc, error) {
	if !r.Valid() {
		return nil, fmt.Errorf("invalid listen range")
	}
	if r.Size() > MaxListenRangePorts {
		return nil, fmt.Errorf("listen range %s exceeds the %d-port ceiling; use a smaller range or the netfilter DNAT deployment mode", r, MaxListenRangePorts)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.primary == nil || b.primary.ipv4 == nil && b.primary.ipv6 == nil {
		return nil, fmt.Errorf("MultiBind.OpenRange: primary port is not open")
	}
	var fns []ReceiveFunc
	added := make(map[uint16]*StdNetBind)
	for p := r.First; ; p++ {
		if p == port {
			// primary port is already bound
			if p == r.Last {
				break
			}
			continue
		}
		if _, exists := b.extras[p]; exists {
			return nil, fmt.Errorf("port %d: already bound in this MultiBind", p)
		}
		sb := NewStdNetBind().(*StdNetBind)
		sbfns, _, err := sb.Open(p)
		if err != nil {
			// roll back the ports opened by this call
			for op, ob := range added {
				ob.Close()
				delete(b.extras, op)
			}
			return nil, fmt.Errorf("failed to listen on port %d (part of range %s): %w", p, r, err)
		}
		b.extras[p] = sb
		added[p] = sb
		for _, fn := range sbfns {
			fns = append(fns, tagReceiveWithPort(fn, p))
		}
		if p == r.Last {
			break
		}
	}
	return fns, nil
}

// tagReceiveWithPort wraps a receive function so that every endpoint it
// produces is tagged with the given local port.
func tagReceiveWithPort(fn ReceiveFunc, port uint16) ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		for i := 0; i < n; i++ {
			if eps[i] != nil {
				eps[i] = &TaggedEndpoint{Endpoint: eps[i], localPort: port}
			}
		}
		return n, err
	}
}

func (b *MultiBind) bindFor(port uint16) *StdNetBind {
	if sb, ok := b.extras[port]; ok {
		return sb
	}
	return b.primary
}

func (b *MultiBind) Send(bufs [][]byte, endpoint Endpoint) error {
	b.mu.Lock()
	var sb *StdNetBind
	switch e := endpoint.(type) {
	case *TaggedEndpoint:
		sb = b.bindFor(e.localPort)
		endpoint = e.Endpoint
	case interface{ PortHint() uint16 }:
		sb = b.bindFor(e.PortHint())
	default:
		sb = b.primary
	}
	b.mu.Unlock()
	return sb.Send(bufs, endpoint)
}

func (b *MultiBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var firstErr error
	if err := b.primary.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	for p, sb := range b.extras {
		if err := sb.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(b.extras, p)
	}
	b.primaryPort = 0
	return firstErr
}

func (b *MultiBind) SetMark(mark uint32) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.primary.SetMark(mark); err != nil {
		return err
	}
	for _, sb := range b.extras {
		if err := sb.SetMark(mark); err != nil {
			return err
		}
	}
	return nil
}

func (b *MultiBind) BatchSize() int {
	return b.primary.BatchSize()
}
