/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
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

// HopConfig holds the client-side port rotation policy shared by every
// RangeEndpoint created by a bind.
type HopConfig struct {
	// Budget is the number of packets sent to one port before rotating to a
	// fresh one. It exists to stay under middlebox per-flow volume limits.
	// 0 disables proactive rotation (a fresh port is still drawn for every
	// handshake attempt).
	Budget uint32
	// Recent is how many previously used ports to avoid when drawing a new
	// one. Bounded by the range size in practice.
	Recent uint32
}

func DefaultHopConfig() HopConfig {
	return HopConfig{
		Budget: 12,
		Recent: 64,
	}
}

// PortRanger is implemented by endpoints that address a destination by a port
// range instead of a single port.
type PortRanger interface {
	Endpoint
	// RangeInfo returns the destination address and the inclusive port range.
	RangeInfo() (netip.Addr, uint16, uint16)
}

// FreshPorter is implemented by range endpoints: it draws a fresh port for a
// new connection attempt (handshake) and returns a fixed-port endpoint that
// also accounts its packets against the rotation budget.
type FreshPorter interface {
	FreshPort() Endpoint
}

// RangeEndpoint addresses a peer as ip:portA-portB. It embeds the hop
// controller: the port assignment policy for packets sent to this endpoint.
//
// RangeEndpoint is created by PortHopBind.ParseEndpoint and is owned by the
// peer's endpoint list; because the endpoint object itself flows through
// Send, the rotation policy travels with it and no Bind/Send interface
// changes are required.
type RangeEndpoint struct {
	mu    sync.Mutex
	inner Bind // inner bind, used to materialize per-port endpoints

	addr netip.Addr
	lo   uint16
	hi   uint16

	cfg HopConfig

	cur   uint16 // current port; 0 until the first assignment
	count uint32 // packets assigned to cur since the last rotation

	recent  []uint16 // ring of recently used ports
	rNext   int
	scratch []uint16 // per-batch port assignment scratch (send path only)

	atPort map[uint16]Endpoint // cache of single-port endpoints per port
}

var (
	_ Endpoint    = (*RangeEndpoint)(nil)
	_ PortRanger  = (*RangeEndpoint)(nil)
	_ FreshPorter = (*RangeEndpoint)(nil)
)

func NewRangeEndpoint(inner Bind, addr netip.Addr, ports PortRange, cfg HopConfig) *RangeEndpoint {
	if !ports.Valid() {
		return nil
	}
	return &RangeEndpoint{
		inner:  inner,
		addr:   addr,
		lo:     ports.First,
		hi:     ports.Last,
		cfg:    cfg,
		atPort: make(map[uint16]Endpoint),
	}
}

func (e *RangeEndpoint) RangeInfo() (netip.Addr, uint16, uint16) {
	return e.addr, e.lo, e.hi
}

// Matches reports whether this endpoint addresses the same destination as the
// given address and inclusive port range.
func (e *RangeEndpoint) Matches(addr netip.Addr, lo, hi uint16) bool {
	return e.addr == addr && e.lo == lo && e.hi == hi
}

func (e *RangeEndpoint) CurrentPort() uint16 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.currentLocked()
}

func (e *RangeEndpoint) currentLocked() uint16 {
	if e.cur == 0 {
		e.rotateLocked()
	}
	return e.cur
}

// rotateLocked draws a fresh port, excluding the current port and recently
// used ones, and resets the budget counter. The caller must hold e.mu.
func (e *RangeEndpoint) rotateLocked() {
	size := uint32(e.hi) - uint32(e.lo) + 1
	exclude := int(e.cfg.Recent)
	if exclude >= int(size) {
		exclude = int(size) - 1
	}
	if exclude < 0 {
		exclude = 0
	}
	p := e.cur
	for tries := 0; tries < 64; tries++ {
		cand := e.lo + uint16(rand.UintN(uint(size)))
		// never stay on the same port across a rotation (a single-port
		// range is the only degenerate case where this is unavoidable)
		if cand == e.cur {
			continue
		}
		if e.inRecentLocked(cand, exclude) {
			continue
		}
		p = cand
		break
	}
	if p == e.cur && size == 1 {
		// degenerate single-port range: rotation is a no-op
		e.count = 0
		return
	}
	if e.cur != 0 && exclude > 0 {
		e.pushRecentLocked(e.cur, exclude)
	}
	e.cur = p
	e.count = 0
}

func (e *RangeEndpoint) inRecentLocked(p uint16, exclude int) bool {
	for i := 0; i < len(e.recent); i++ {
		if e.recent[i] == p {
			return true
		}
	}
	return false
}

func (e *RangeEndpoint) pushRecentLocked(p uint16, exclude int) {
	if len(e.recent) < exclude {
		e.recent = append(e.recent, p)
		return
	}
	e.recent[e.rNext] = p
	e.rNext = (e.rNext + 1) % len(e.recent)
}

// AssignPorts fills dst[0:n] with per-packet destination ports, rotating at
// budget boundaries. Runs of identical ports are contiguous by construction so
// that the caller can batch per port.
func (e *RangeEndpoint) AssignPorts(dst []uint16, n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.assignPortsLocked(dst[:n])
}

func (e *RangeEndpoint) assignPortsLocked(dst []uint16) {
	for i := range dst {
		if e.cur == 0 || (e.cfg.Budget > 0 && e.count >= e.cfg.Budget) {
			e.rotateLocked()
		}
		dst[i] = e.cur
		e.count++
	}
}

// addCount records that n packets were sent on the current port through a
// fixed-port child endpoint (handshake attempts).
func (e *RangeEndpoint) addCount(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.count += uint32(n)
}

// FreshPort draws a fresh port for a new connection attempt and returns a
// fixed-port endpoint bound to it; packets sent through the returned endpoint
// are counted against the rotation budget.
func (e *RangeEndpoint) FreshPort() Endpoint {
	e.mu.Lock()
	e.rotateLocked()
	port := e.cur
	e.mu.Unlock()
	return &attemptEndpoint{
		parent: e,
		inner:  e.endpointFor(port),
	}
}

// AtPort returns a fixed-port endpoint for the given port. Used by the bind
// when splitting a batch across rotation boundaries; fixed-port endpoints do
// not count toward the budget (AssignPorts already did).
func (e *RangeEndpoint) AtPort(port uint16) Endpoint {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.endpointFor(port)
}

// endpointFor returns the inner bind's single-port endpoint for port,
// creating and caching it if necessary. The caller must hold e.mu.
func (e *RangeEndpoint) endpointFor(port uint16) Endpoint {
	if ep, ok := e.atPort[port]; ok {
		return ep
	}
	ap := netip.AddrPortFrom(e.addr, port)
	ep, err := e.inner.ParseEndpoint(ap.String())
	if err != nil {
		// Should not happen for well-formed binds; fall back to a plain
		// StdNetEndpoint so sends still carry a valid destination.
		ep = &StdNetEndpoint{AddrPort: ap}
	}
	e.atPort[port] = ep
	return ep
}

// attemptEndpoint is a fixed-port view of a RangeEndpoint used for a single
// connection attempt (handshake burst). Packets sent through it are counted
// against the parent's budget.
type attemptEndpoint struct {
	parent *RangeEndpoint
	inner  Endpoint
}

var _ Endpoint = (*attemptEndpoint)(nil)

// countedParent is implemented by attemptEndpoint so the bind can account
// packets sent through it against the rotation budget.
type countedParent interface {
	countedEndpoint() Endpoint
	countPackets(n int)
}

func (a *attemptEndpoint) countedEndpoint() Endpoint { return a.inner }
func (a *attemptEndpoint) countPackets(n int)        { a.parent.addCount(n) }

func (a *attemptEndpoint) ClearSrc() { a.inner.ClearSrc() }
func (a *attemptEndpoint) SrcToString() string {
	return a.inner.SrcToString()
}
func (a *attemptEndpoint) DstToString() string { return a.inner.DstToString() }
func (a *attemptEndpoint) DstToBytes() []byte  { return a.inner.DstToBytes() }
func (a *attemptEndpoint) DstIP() netip.Addr   { return a.inner.DstIP() }
func (a *attemptEndpoint) SrcIP() netip.Addr   { return a.inner.SrcIP() }
func (a *attemptEndpoint) DstIPPort() netip.AddrPort {
	return a.inner.DstIPPort()
}

// Endpoint interface of RangeEndpoint: the destination is rendered as the
// range itself; DstIPPort uses the current port (display/matching only).

func (e *RangeEndpoint) ClearSrc() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ep := range e.atPort {
		ep.ClearSrc()
	}
}

func (e *RangeEndpoint) SrcToString() string { return "(-)" }

func (e *RangeEndpoint) DstToString() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return netip.AddrPortFrom(e.addr, e.currentLocked()).String() +
		fmt.Sprintf(" (range %d-%d)", e.lo, e.hi)
}

func (e *RangeEndpoint) DstToBytes() []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	ap := netip.AddrPortFrom(e.addr, e.currentLocked())
	b, _ := ap.MarshalBinary()
	return b
}

func (e *RangeEndpoint) DstIP() netip.Addr { return e.addr }

func (e *RangeEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

func (e *RangeEndpoint) DstIPPort() netip.AddrPort {
	e.mu.Lock()
	defer e.mu.Unlock()
	return netip.AddrPortFrom(e.addr, e.currentLocked())
}

// parseRangeEndpointString parses "ip:portA-portB" (and "ip:port",
// "ip"). It returns ok=false when the string carries no range suffix.
func parseRangeEndpointString(s string) (netip.Addr, PortRange, bool, error) {
	addr, err := netip.ParseAddr(s)
	if err == nil {
		// bare address, no port information
		return addr, PortRange{}, false, nil
	}
	host, ports, err := net.SplitHostPort(s)
	if err != nil {
		return netip.Addr{}, PortRange{}, false, nil
	}
	first, rest, hasDash := strings.Cut(ports, "-")
	if !hasDash {
		return netip.Addr{}, PortRange{}, false, nil
	}
	lo, err := strconv.ParseUint(first, 10, 16)
	if err != nil {
		return netip.Addr{}, PortRange{}, false, nil
	}
	hi, err := strconv.ParseUint(rest, 10, 16)
	if err != nil {
		return netip.Addr{}, PortRange{}, false, nil
	}
	addr, err = netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, PortRange{}, false, nil
	}
	if lo == 0 || hi == 0 || lo > hi {
		return netip.Addr{}, PortRange{}, false, fmt.Errorf("invalid port range %q", ports)
	}
	return addr, PortRange{First: uint16(lo), Last: uint16(hi)}, true, nil
}
