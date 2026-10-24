/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"net/netip"
	"sync"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
)

// hopRetryDelay is how long the send path waits before re-trying a hop source
// that recently returned an error (e.g. the port pool is fully cooling down).
const hopRetryDelay = time.Second

// HopSource supplies replacement carrying endpoints for a peer whose
// destinations are configured as port ranges (port hopping). It is
// implemented by the nylon core: the port pool draws a fresh,
// diversity-maximising addr:port and materialises the matching nylon endpoint
// for probing and ranking.
//
// Implementations MUST be safe for concurrent use and fast (no I/O): they are
// called from the packet send path. In particular, NextHopEndpoint runs while
// the caller (Peer.SendBuffers) holds the device net lock in READ mode, so
// implementations MUST NOT acquire Device.Bind() (or anything else that takes
// the device net WRITE lock) — doing so self-deadlocks: the write lock can
// never be granted while the caller's own read lock is still held.
type HopSource interface {
	// NextHopEndpoint returns the endpoint that should carry traffic after
	// the given endpoint was exhausted. exhausted is nil when the first
	// carrying endpoint is drawn.
	NextHopEndpoint(peer *Peer, exhausted conn.Endpoint) (conn.Endpoint, error)
}

// hopState is the per-peer port rotation state. A nil hop (or budget <= 0)
// leaves the peer on stock endpoint behaviour.
type hopState struct {
	mu            sync.Mutex
	src           HopSource
	budget        int // wire packets per carrying port
	current       conn.Endpoint
	left          int
	degradedUntil time.Time // source error backoff
}

// SetHop installs (or, with a nil source, clears) the port hopping policy for
// the peer. budget is the number of wire packets a carrying port may receive
// before rotation; budget <= 0 disables hopping.
func (peer *Peer) SetHop(src HopSource, budget int) {
	if src == nil || budget <= 0 {
		peer.hop.Store(nil)
		return
	}
	h := peer.hop.Load()
	if h != nil {
		h.mu.Lock()
		h.src = src
		h.budget = budget
		h.mu.Unlock()
		return
	}
	peer.hop.Store(&hopState{src: src, budget: budget})
}

// hopCarrying returns the endpoint that should carry NEW packets, rotating
// first when the current port's budget is spent. It returns nil when hopping
// is inactive (caller falls back to stock behaviour) or when the source is
// unavailable.
func (peer *Peer) hopCarrying() conn.Endpoint {
	h := peer.hop.Load()
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if !h.degradedUntil.IsZero() && now.Before(h.degradedUntil) {
		return h.current
	}
	if h.current == nil || h.left <= 0 {
		next, err := h.src.NextHopEndpoint(peer, h.current)
		if err != nil {
			h.degradedUntil = now.Add(hopRetryDelay)
			peer.device.Log.Verbosef("%v - hop source unavailable, stock endpoint behaviour for %s: %v", peer, hopRetryDelay, err)
			return h.current
		}
		h.current = next
		h.left = h.budget
	}
	return h.current
}

// hopHasCurrent reports whether a carrying endpoint is already drawn, without
// drawing one. Used to relax the "no known endpoints" guard while the first
// endpoint is still being established.
func (peer *Peer) hopHasCurrent() bool {
	h := peer.hop.Load()
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.current != nil
}

// HopStatus is the port hopping state of a peer, exposed for observability.
type HopStatus struct {
	Carrying   string // destination of the current carrying endpoint ("" before the first draw)
	Budget     int    // per-port wire packet budget
	BudgetLeft int    // packets left on the carrying port
}

// HopStatus reports the port hopping state of the peer. The second return
// value is false when hopping is not active for this peer.
func (peer *Peer) HopStatus() (HopStatus, bool) {
	h := peer.hop.Load()
	if h == nil {
		return HopStatus{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	st := HopStatus{Budget: h.budget, BudgetLeft: h.left}
	if h.current != nil {
		st.Carrying = h.current.DstToString()
	}
	return st, true
}

// hopAccountSend enforces the per-port packet budget on an outgoing batch.
// Every buffer addressed to the batch's carrying endpoint decrements the
// budget; once the budget is spent the carrying endpoint rotates and the
// remaining buffers of the batch (including those still addressed to the
// rotated-away endpoint) are re-addressed to the new endpoint, so no port
// exceeds its budget mid-batch. Buffers addressed elsewhere (e.g.
// handshakes to a roaming source) are left untouched.
//
// eps is the caller's slice and is mutated in place.
func (peer *Peer) hopAccountSend(eps []conn.Endpoint) {
	h := peer.hop.Load()
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if !h.degradedUntil.IsZero() && now.Before(h.degradedUntil) {
		return
	}
	if h.current == nil {
		return
	}
	// target is the endpoint this batch's matched buffers are re-addressed to;
	// it follows every mid-batch rotation. base is the endpoint the matched
	// buffers were originally addressed to (the carrying endpoint at batch
	// start): after a mid-batch rotation, buffers still addressed to base
	// must follow the rotation rather than stay on the burned port.
	target := h.current
	var base netip.AddrPort
	for i := range eps {
		if eps[i] == nil {
			continue
		}
		dst := eps[i].DstIPPort()
		if base.IsValid() {
			if dst != base && dst != target.DstIPPort() {
				continue
			}
		} else {
			if dst != target.DstIPPort() {
				continue
			}
			base = dst
		}
		if h.left <= 0 {
			next, err := h.src.NextHopEndpoint(peer, h.current)
			if err != nil {
				// Keep the remainder on the current port: overshooting the
				// budget by a few packets beats dropping them.
				h.degradedUntil = now.Add(hopRetryDelay)
				peer.device.Log.Verbosef("%v - hop rotation stalled, finishing batch on %v: %v", peer, target.DstToString(), err)
				return
			}
			h.current = next
			h.left = h.budget
			target = next
		}
		eps[i] = target
		h.left--
	}
}
