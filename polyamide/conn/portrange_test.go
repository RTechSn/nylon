/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"fmt"
	"net/netip"
	"testing"
)

func TestParsePortRange(t *testing.T) {
	cases := []struct {
		in      string
		first   uint16
		last    uint16
		wantErr bool
	}{
		{in: "57175", first: 57175, last: 57175},
		{in: "30000-40000", first: 30000, last: 40000},
		{in: "443-443", first: 443, last: 443},
		{in: "1-65535", first: 1, last: 65535},
		{in: "0", wantErr: true},
		{in: "0-100", wantErr: true},
		{in: "40000-30000", wantErr: true},
		{in: "70000", wantErr: true},
		{in: "30000-70000", wantErr: true},
		{in: "", wantErr: true},
		{in: "abc", wantErr: true},
		{in: "1-2-3", wantErr: true},
	}
	for _, tc := range cases {
		pr, err := ParsePortRange(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParsePortRange(%q): expected error, got %v", tc.in, pr)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePortRange(%q): unexpected error %v", tc.in, err)
			continue
		}
		if pr.First != tc.first || pr.Last != tc.last {
			t.Errorf("ParsePortRange(%q) = %v, want %d-%d", tc.in, pr, tc.first, tc.last)
		}
	}
}

func testRangeEndpoint(t *testing.T, lo, hi, budget, recent uint32) *RangeEndpoint {
	t.Helper()
	inner := NewStdNetBind()
	ep := NewRangeEndpoint(inner, netip.MustParseAddr("127.0.0.1"), PortRange{First: uint16(lo), Last: uint16(hi)}, HopConfig{Budget: budget, Recent: recent})
	if ep == nil {
		t.Fatal("NewRangeEndpoint returned nil")
	}
	return ep
}

func TestRangeEndpointBudgetRotation(t *testing.T) {
	const (
		lo     = 30000
		hi     = 30010
		budget = 4
	)
	ep := testRangeEndpoint(t, lo, hi, budget, 0)

	var ports []uint16
	assigned := make([]uint16, 64)
	ep.AssignPorts(assigned, len(assigned))
	ports = append(ports, assigned...)

	// all ports inside the range
	for i, p := range ports {
		if p < lo || p > hi {
			t.Fatalf("port %d out of range: %d", i, p)
		}
	}
	// contiguous runs of the same port must not exceed the budget
	run := 1
	for i := 1; i < len(ports); i++ {
		if ports[i] == ports[i-1] {
			run++
			if run > budget {
				t.Fatalf("run of port %d exceeded budget %d", ports[i], budget)
			}
		} else {
			run = 1
		}
	}
	// rotation must actually happen across a long enough sample
	uniq := map[uint16]int{}
	for _, p := range ports {
		uniq[p]++
	}
	if len(uniq) < 3 {
		t.Fatalf("expected rotation across several ports, only used %v", uniq)
	}
}

func TestRangeEndpointRecentExclusion(t *testing.T) {
	const (
		lo     = 40000
		hi     = 40004 // 5 ports
		budget = 1
		recent = 3
	)
	ep := testRangeEndpoint(t, lo, hi, budget, recent)

	seen := make([]uint16, 0, 32)
	assigned := make([]uint16, 1)
	for i := 0; i < 32; i++ {
		ep.AssignPorts(assigned, 1)
		seen = append(seen, assigned[0])
	}
	// every port must differ from the previous `recent` ports
	for i, p := range seen {
		back := i - 1
		for j := 0; j < int(recent) && back >= 0; j++ {
			if seen[back] == p {
				t.Fatalf("port %d at index %d reuses recent port %d (index %d)", p, i, seen[back], back)
			}
			back--
		}
	}
}

func TestRangeEndpointFreshPort(t *testing.T) {
	ep := testRangeEndpoint(t, 50000, 50099, 8, 16)

	first := ep.FreshPort()
	fp, ok := first.(*attemptEndpoint)
	if !ok {
		t.Fatalf("FreshPort returned %T, want *attemptEndpoint", first)
	}
	ap := fp.DstIPPort()
	if ap.Port() < 50000 || ap.Port() > 50099 {
		t.Fatalf("fresh port out of range: %v", ap)
	}

	// a fresh attempt must move to a different port (recent exclusion)
	second := ep.FreshPort().DstIPPort()
	if second == ap {
		t.Fatalf("FreshPort reused the same port %v", ap)
	}

	// counted packets accumulate on the parent budget
	before := ep.CurrentPort()
	_ = before
	fp2 := ep.FreshPort().(*attemptEndpoint)
	fp2.countPackets(3)
	if ep.budgetCount() != 3 {
		t.Fatalf("expected 3 counted packets, got %d", ep.budgetCount())
	}
}

func (e *RangeEndpoint) budgetCount() uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.count
}

// captureBind records every Send call.
type captureBind struct {
	inner Bind
	calls []captureCall
}

type captureCall struct {
	dst  Endpoint
	bufs int
}

func (c *captureBind) Open(port uint16) ([]ReceiveFunc, uint16, error) { return nil, port, nil }
func (c *captureBind) Close() error                                    { return nil }
func (c *captureBind) SetMark(mark uint32) error                       { return nil }
func (c *captureBind) BatchSize() int                                  { return IdealBatchSize }
func (c *captureBind) ParseEndpoint(s string) (Endpoint, error) {
	return c.inner.ParseEndpoint(s)
}
func (c *captureBind) Send(bufs [][]byte, ep Endpoint) error {
	c.calls = append(c.calls, captureCall{dst: ep, bufs: len(bufs)})
	return nil
}

func TestPortHopBindSendsRunsPerBudget(t *testing.T) {
	inner := NewStdNetBind()
	cap := &captureBind{inner: inner}
	bind := NewPortHopBind(cap, HopConfig{Budget: 4, Recent: 8})

	ep, err := bind.ParseEndpoint("127.0.0.1:30000-30010")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ep.(*RangeEndpoint); !ok {
		t.Fatalf("expected *RangeEndpoint, got %T", ep)
	}

	bufs := make([][]byte, 10)
	for i := range bufs {
		bufs[i] = []byte{byte(i)}
	}
	if err := bind.Send(bufs, ep); err != nil {
		t.Fatal(err)
	}

	// 10 packets with a budget of 4 must split into at least 3 runs
	if len(cap.calls) < 3 {
		t.Fatalf("expected >= 3 send runs, got %d: %+v", len(cap.calls), cap.calls)
	}
	total := 0
	for i, call := range cap.calls {
		if call.bufs > 4 {
			t.Fatalf("run %d has %d bufs, exceeds budget", i, call.bufs)
		}
		ap := call.dst.DstIPPort()
		if ap.Port() < 30000 || ap.Port() > 30010 {
			t.Fatalf("run %d dst port %v out of range", i, ap)
		}
		total += call.bufs
	}
	if total != 10 {
		t.Fatalf("expected 10 total bufs, got %d", total)
	}

	// single-port endpoints pass through untouched
	plain, err := bind.ParseEndpoint("127.0.0.1:57175")
	if err != nil {
		t.Fatal(err)
	}
	n := len(cap.calls)
	if err := bind.Send(bufs[:1], plain); err != nil {
		t.Fatal(err)
	}
	if len(cap.calls) != n+1 {
		t.Fatal("expected passthrough send for single-port endpoint")
	}
	if cap.calls[n].bufs != 1 {
		t.Fatalf("passthrough sent %d bufs", cap.calls[n].bufs)
	}
}

func TestPortHopBindFreshAttemptAccounting(t *testing.T) {
	inner := NewStdNetBind()
	cap := &captureBind{inner: inner}
	bind := NewPortHopBind(cap, HopConfig{Budget: 4, Recent: 8})

	ep, err := bind.ParseEndpoint("127.0.0.1:30000-30010")
	if err != nil {
		t.Fatal(err)
	}
	re := ep.(*RangeEndpoint)
	attempt := re.FreshPort()

	bufs := make([][]byte, 3)
	for i := range bufs {
		bufs[i] = []byte{1}
	}
	if err := bind.Send(bufs, attempt); err != nil {
		t.Fatal(err)
	}
	if len(cap.calls) != 1 {
		t.Fatalf("attempt burst should be a single run, got %d", len(cap.calls))
	}
	if got := re.budgetCount(); got != 3 {
		t.Fatalf("expected 3 accounted packets, got %d", got)
	}
}

func TestRangeEndpointStringForms(t *testing.T) {
	ep, err := NewPortHopBind(NewStdNetBind(), HopConfig{}).ParseEndpoint("[2001:db8::1]:30000-40000")
	if err != nil {
		t.Fatal(err)
	}
	addr, lo, hi := ep.(*RangeEndpoint).RangeInfo()
	if addr != netip.MustParseAddr("2001:db8::1") || lo != 30000 || hi != 40000 {
		t.Fatalf("unexpected range info: %v %d-%d", addr, lo, hi)
	}
	s := ep.DstToString()
	wantPrefix := "[2001:db8::1]:"
	if len(s) < len(wantPrefix) || s[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("DstToString = %q, want prefix %q", s, wantPrefix)
	}
}

var _ = fmt.Sprintf // keep fmt for debugging aids
