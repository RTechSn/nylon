/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// TestMultiBindRangeListenAndReply verifies the server half of port hopping:
// a MultiBind listens on a primary port plus a range; packets to any port in
// the range are received with a port hint, and a reply sent back to that
// endpoint leaves from exactly the port the client wrote to.
func TestMultiBindRangeListenAndReply(t *testing.T) {
	mb := NewMultiBind()

	// pick a free primary port
	resolver, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.ListenUDP("udp", resolver)
	if err != nil {
		t.Fatal(err)
	}
	primaryPort := uint16(probe.LocalAddr().(*net.UDPAddr).Port)
	probe.Close()

	fns, actual, err := mb.Open(primaryPort)
	if err != nil {
		t.Fatal(err)
	}
	if actual != primaryPort {
		t.Fatalf("primary port %d != requested %d", actual, primaryPort)
	}

	// choose a free range of 4 ports above the primary port
	lo := primaryPort + 100
	if lo > 65000 {
		lo = primaryPort - 100 - 4
	}
	hi := lo + 3

	extraFns, err := mb.OpenRange(primaryPort, PortRange{First: lo, Last: hi})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mb.Close() })

	type received struct {
		data []byte
		ep   Endpoint
	}
	rx := make(chan received, 32)
	spawn := func(fns []ReceiveFunc) {
		for _, fn := range fns {
			fn := fn
			go func() {
				bufs := make([][]byte, 1)
				bufs[0] = make([]byte, 128)
				sizes := make([]int, 1)
				eps := make([]Endpoint, 1)
				for {
					n, err := fn(bufs, sizes, eps)
					if err != nil {
						return
					}
					for i := 0; i < n; i++ {
						if sizes[i] > 0 {
							rx <- received{data: append([]byte(nil), bufs[0][:sizes[i]]...), ep: eps[i]}
						}
					}
				}
			}()
		}
	}
	spawn(fns)
	spawn(extraFns)

	// a client socket writes to a port inside the range
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })

	targetPort := lo + 2
	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(targetPort)}
	msg := []byte("ping")
	if _, err := client.WriteToUDP(msg, target); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-rx:
		if string(got.data) != "ping" {
			t.Fatalf("unexpected payload %q", got.data)
		}
		if got.ep == nil {
			t.Fatal("nil endpoint")
		}
		// the endpoint must carry the local port hint
		hinter, ok := got.ep.(interface{ PortHint() uint16 })
		if !ok {
			t.Fatalf("endpoint %T lacks PortHint", got.ep)
		}
		if got := hinter.PortHint(); got != targetPort {
			t.Fatalf("port hint = %d, want %d", got, targetPort)
		}
		// reply through the MultiBind; it must leave from the same port
		if err := mb.Send([][]byte{[]byte("pong")}, got.ep); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := client.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("client did not receive reply: %v", err)
		}
		if string(buf[:n]) != "pong" {
			t.Fatalf("unexpected reply %q", buf[:n])
		}
		if from.Port != int(targetPort) {
			t.Fatalf("reply src port = %d, want %d", from.Port, targetPort)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no packet received on range port")
	}
}

// TestMultiBindPrimaryStillWorks ensures the primary port keeps receiving and
// replying (untagged endpoints default to the primary socket).
func TestMultiBindPrimaryStillWorks(t *testing.T) {
	mb := NewMultiBind()
	resolver, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	probe, err := net.ListenUDP("udp", resolver)
	if err != nil {
		t.Fatal(err)
	}
	primaryPort := uint16(probe.LocalAddr().(*net.UDPAddr).Port)
	probe.Close()

	fns, _, err := mb.Open(primaryPort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mb.Close() })

	type received struct {
		ep Endpoint
	}
	rx := make(chan received, 8)
	for _, fn := range fns {
		fn := fn
		go func() {
			bufs := make([][]byte, 1)
			bufs[0] = make([]byte, 128)
			sizes := make([]int, 1)
			eps := make([]Endpoint, 1)
			for {
				n, err := fn(bufs, sizes, eps)
				if err != nil {
					return
				}
				for i := 0; i < n; i++ {
					if sizes[i] > 0 {
						rx <- received{ep: eps[i]}
					}
				}
			}
		}()
	}

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(primaryPort)}
	if _, err := client.WriteToUDP([]byte("hi"), target); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-rx:
		// plain (untagged) endpoint: send must route via the primary socket
		if err := mb.Send([][]byte{[]byte("yo")}, got.ep); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := client.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != "yo" || from.Port != int(primaryPort) {
			t.Fatalf("unexpected reply %q from %v", buf[:n], from)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no packet received on primary port")
	}
}

// TestMultiBindRangeCeiling verifies the range-size guard.
func TestMultiBindRangeCeiling(t *testing.T) {
	mb := NewMultiBind()
	fns, port, err := mb.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer mb.Close()
	_ = fns

	huge := PortRange{First: 1, Last: uint16(MaxListenRangePorts + 100)}
	if _, err := mb.OpenRange(port, huge); err == nil {
		t.Fatal("expected ceiling error for oversized range")
	}
}

// TestRangeOpenerPortSkipInsideRange verifies the primary port inside the
// range is not double-bound.
func TestRangeOpenerPortSkipInsideRange(t *testing.T) {
	mb := NewMultiBind()
	_, port, err := mb.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer mb.Close()

	r := PortRange{First: port, Last: port + 2}
	if _, err := mb.OpenRange(port, r); err != nil {
		t.Fatalf("OpenRange with primary inside range failed: %v", err)
	}
}

var _ = netip.MustParseAddrPort
var _ = strconv.Itoa
