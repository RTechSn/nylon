/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"sync"
)

// JunkSpec is a resolved sender-local junk configuration: the AWG J trio
// (`Jc` junk datagrams of sizes drawn from [Jmin, Jmax)) plus the i1..i5
// packet specs ("" = unset). The zero value emits no junk.
type JunkSpec struct {
	Jc, Jmin, Jmax uint32
	I              [5]string
}

// JunkSource supplies the junk prepended to every handshake initiation toward
// one peer — the per-strategy junk of the connection the peer's carrying
// endpoint belongs to. It is implemented by the nylon core, mirroring the
// HopSource pattern established for port hopping: junk PARAMETERS live in
// the controller (they are obf strategy properties), the junk BYTES stay
// produced by polyamide (the datagram draw and the i-packet obfuscation
// chains below) — a source cannot invent a packet shape.
//
// Implementations MUST be safe for concurrent use and fast (no I/O): they
// are consulted from the packet send path (SendHandshakeInitiation). Unlike
// NextHopEndpoint, the consult runs BEFORE the caller enters SendBuffers, so
// the device net lock is not held — but the same discipline applies (the
// send path must never wait on the controller).
type JunkSource interface {
	// JunkFor returns the junk configuration for handshake initiations
	// toward peer. ok == false falls back to the device-global UAPI knobs
	// (jc/jmin/jmax, i1..i5) — stock behaviour for everything configured
	// through UAPI. ok == true with a ZERO spec suppresses junk for the
	// peer: a junkless strategy must not leak the device fallback.
	JunkFor(peer *Peer) (JunkSpec, bool)
}

// JunkLabeler is optionally implemented by JunkSource implementations that
// can name the junk configuration they currently serve (the nylon core names
// the obf strategy carrying the peer's connection). The label is purely
// informational — surfaced in the UAPI dump next to the hop status.
type JunkLabeler interface {
	JunkLabel() string
}

// junkState is the per-peer junk hook state. A nil state (or a nil source)
// leaves the peer on stock device-knob behaviour.
type junkState struct {
	mu  sync.Mutex
	src JunkSource
}

// SetJunkSource installs (or, with nil, clears) the per-peer junk source for
// handshake initiations. The peer's WireGuard session is untouched: junk is
// a prepend decoration of initiations, not a property of the keypair, so a
// source can be swapped (or a spec changed) at any time — the next
// initiation simply speaks the new junk.
func (peer *Peer) SetJunkSource(src JunkSource) {
	if src == nil {
		peer.junk.Store(nil)
		return
	}
	st := peer.junk.Load()
	if st != nil {
		st.mu.Lock()
		st.src = src
		st.mu.Unlock()
		return
	}
	peer.junk.Store(&junkState{src: src})
}

// junkSpec consults the hook, if one is wired: the junk configuration the
// NEXT handshake initiation toward this peer must speak. ok == false means
// no source is installed (or its current answer is "not mine to decide") —
// the caller falls back to the device-global UAPI knobs.
func (peer *Peer) junkSpec() (JunkSpec, bool) {
	st := peer.junk.Load()
	if st == nil {
		return JunkSpec{}, false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.src.JunkFor(peer)
}

// JunkStatus reports the peer's active junk hook for observability (the UAPI
// dump): a live consult, the same call the next handshake's prepend assembly
// makes. active is false when no source is wired (the device knobs carry the
// peer). The label names the configuration when the source implements
// JunkLabeler.
func (peer *Peer) JunkStatus() (spec JunkSpec, label string, active bool) {
	st := peer.junk.Load()
	if st == nil {
		return JunkSpec{}, "", false
	}
	st.mu.Lock()
	src := st.src
	st.mu.Unlock()
	spec, active = peer.junkSpec()
	if l, ok := src.(JunkLabeler); ok {
		label = l.JunkLabel()
	}
	return spec, label, true
}

// chainFor parses (once) and returns the cached obfuscation chain of an
// i-packet spec string. An empty or tagless spec yields a nil chain (no
// i-packet — the same nil the UAPI i1..i5 parse produces). A spec that
// fails to parse — unreachable through nylon, whose validation pins every
// strategy i-spec with ValidateObfSpec — degrades to no i-packet with one
// error line per distinct spec rather than killing the send path.
//
// The cache maps per distinct spec string; chains are immutable, so a
// benign double-parse on a cold race is harmless.
func (device *Device) chainFor(spec string) *obfChain {
	if spec == "" {
		return nil
	}
	device.ichains.mu.Lock()
	c, ok := device.ichains.m[spec]
	device.ichains.mu.Unlock()
	if ok {
		return c
	}
	c, err := newObfChain(spec)
	if err != nil {
		device.Log.Errorf("junk: unparseable i-packet spec %q, emitting no i-packet: %v", spec, err)
		c = nil
	}
	device.ichains.mu.Lock()
	if device.ichains.m == nil {
		device.ichains.m = make(map[string]*obfChain)
	}
	device.ichains.m[spec] = c
	device.ichains.mu.Unlock()
	return c
}

// iPacketBuffers renders the prepend buffers of a parsed i-chain set (nil
// slots emit nothing) — the exact buffers SendHandshakeInitiation prepends
// to the initiation, in wire order.
func (device *Device) iPacketBuffers(chains [5]*obfChain) [][]byte {
	var bufs [][]byte
	for _, c := range chains {
		if c == nil {
			continue
		}
		buf := make([]byte, c.ObfuscatedLen(0))
		c.Obfuscate(buf, nil)
		bufs = append(bufs, buf)
	}
	return bufs
}

// specIPacketBuffers renders the prepend buffers of a spec's i-set, parsing
// each distinct spec once through the device-wide cache.
func (device *Device) specIPacketBuffers(specs [5]string) [][]byte {
	var chains [5]*obfChain
	for i, s := range specs {
		chains[i] = device.chainFor(s)
	}
	return device.iPacketBuffers(chains)
}

// junkPackets draws `count` random junk datagrams of sizes drawn from
// [min, max) — the AWG J-stream. count == 0 (or an inverted range, which no
// validated configuration produces) emits nothing.
func (device *Device) junkPackets(count, min, max uint32) [][]byte {
	if count == 0 || max < min {
		return nil
	}
	bufs := make([][]byte, 0, count)
	for range count {
		buf := make([]byte, min+fastrandn(max-min))
		rand.Read(buf)
		bufs = append(bufs, buf)
	}
	return bufs
}
