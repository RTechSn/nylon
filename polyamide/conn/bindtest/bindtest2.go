/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package bindtest

import (
	"net"
	"net/netip"
	"sync"

	"github.com/encodeous/nylon/polyamide/conn"
)

type chanPkt struct {
	data   []byte
	remote ChannelEndpoint2
	// srcHint is the source port the sender chose for this packet: the local
	// (listening) port a range-listener received the replied-to packet on
	// (port-hopping reply symmetry), or 0 when the sender carries no hint
	// (single-port bind). Received packets expose the hint through a
	// HintedEndpoint so devices roam onto it and replies return through the
	// same port, mirroring the real MultiBind's TaggedEndpoint routing.
	srcHint uint16
}

type ChannelBind2 struct {
	rx, tx      *chan chanPkt
	closeSignal chan bool

	// tosMu guards tosCounts: outgoing packet counts per destination
	// endpoint and TOS byte (test seam for the outer DSCP marking — plain
	// Send records 0, SendTOS records the stamped byte).
	tosMu     sync.Mutex
	tosCounts map[ChannelEndpoint2]map[byte]uint64
}

type ChannelEndpoint2 netip.AddrPort

// HintedEndpoint is a ChannelEndpoint2 annotated with the local port the
// packet it describes arrived on (port hopping): replies to a hinted
// endpoint must originate from that port, exactly like the real
// conn.TaggedEndpoint produced by the range listener's receive functions.
// It is a comparable value type so endpoint-change detection keeps working.
type HintedEndpoint struct {
	Dst     ChannelEndpoint2
	SrcPort uint16
}

var _ conn.Endpoint = HintedEndpoint{}
var _ interface{ PortHint() uint16 } = HintedEndpoint{}

// NewHintedEndpoint wraps a destination endpoint with the local (arrival)
// port hint.
func NewHintedEndpoint(dst ChannelEndpoint2, srcPort uint16) HintedEndpoint {
	return HintedEndpoint{Dst: dst, SrcPort: srcPort}
}

// PortHint returns the local port replies to this endpoint must originate
// from.
func (h HintedEndpoint) PortHint() uint16 { return h.SrcPort }

func (h HintedEndpoint) ClearSrc() {}

func (h HintedEndpoint) SrcToString() string { return "" }

func (h HintedEndpoint) DstToString() string { return h.Dst.DstToString() }

func (h HintedEndpoint) DstToBytes() []byte { return h.Dst.DstToBytes() }

func (h HintedEndpoint) DstIP() netip.Addr { return h.Dst.DstIP() }

func (h HintedEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

func (h HintedEndpoint) DstIPPort() netip.AddrPort { return h.Dst.DstIPPort() }

// EndpointDstOf unwraps a receive-path endpoint into its destination
// endpoint and the source-port hint it carries (0 when absent).
func EndpointDstOf(ep conn.Endpoint) (ChannelEndpoint2, uint16) {
	switch e := ep.(type) {
	case ChannelEndpoint2:
		return e, 0
	case HintedEndpoint:
		return e.Dst, e.SrcPort
	default:
		// foreign endpoint types (e.g. wrapped during forwarding): fall back
		// to the endpoint's own address
		return ChannelEndpoint2(ep.DstIPPort()), 0
	}
}

var (
	_ conn.Bind     = (*ChannelBind2)(nil)
	_ conn.TOSBind  = (*ChannelBind2)(nil)
	_ conn.Endpoint = (*ChannelEndpoint2)(nil)
)

func NewChannelBind2() [2]conn.Bind {
	arx4 := make(chan chanPkt, 8192)
	brx4 := make(chan chanPkt, 8192)
	var binds [2]ChannelBind2
	binds[0].rx = &arx4
	binds[0].tx = &brx4

	binds[1].rx = &brx4
	binds[1].tx = &arx4

	return [2]conn.Bind{&binds[0], &binds[1]}
}

func (c ChannelEndpoint2) ClearSrc() {}

func (c ChannelEndpoint2) SrcToString() string { return "" }

func (c ChannelEndpoint2) DstToString() string {
	return netip.AddrPort(c).String()
}

func (c ChannelEndpoint2) DstToBytes() []byte {
	addr := netip.AddrPort(c)
	b, _ := addr.MarshalBinary()
	return b
}

func (c ChannelEndpoint2) DstIP() netip.Addr {
	return netip.AddrPort(c).Addr()
}

func (c ChannelEndpoint2) SrcIP() netip.Addr { return netip.Addr{} }
func (c ChannelEndpoint2) DstIPPort() netip.AddrPort {
	return netip.AddrPort(c)
}

func (c *ChannelBind2) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	c.closeSignal = make(chan bool)
	fns = append(fns, c.makeReceiveFunc(*c.rx))
	return fns, port, nil
}

func (c *ChannelBind2) Close() error {
	if c.closeSignal != nil {
		select {
		case <-c.closeSignal:
		default:
			close(c.closeSignal)
		}
	}
	return nil
}

func (c *ChannelBind2) BatchSize() int { return 1 }

func (c *ChannelBind2) SetMark(mark uint32) error { return nil }

func (c *ChannelBind2) makeReceiveFunc(ch chan chanPkt) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		select {
		case <-c.closeSignal:
			return 0, net.ErrClosed
		case rx := <-ch:
			copied := copy(bufs[0], rx.data)
			sizes[0] = copied
			if rx.srcHint != 0 {
				eps[0] = NewHintedEndpoint(rx.remote, rx.srcHint)
			} else {
				eps[0] = rx.remote
			}
			return 1, nil
		}
	}
}

// channelEndpointOf unwraps a send-path endpoint into its destination and
// the source-port hint it carries (0 when absent).
func channelEndpointOf(ep conn.Endpoint) (ChannelEndpoint2, uint16) {
	switch e := ep.(type) {
	case ChannelEndpoint2:
		return e, 0
	case HintedEndpoint:
		return e.Dst, e.SrcPort
	default:
		ap := ep.DstIPPort()
		remote := ChannelEndpoint2(ap)
		if h, ok := ep.(interface{ PortHint() uint16 }); ok {
			return remote, h.PortHint()
		}
		return remote, 0
	}
}

// recordTOS notes the TOS byte carried by an outgoing batch (0 for a plain
// Send).
func (c *ChannelBind2) recordTOS(remote ChannelEndpoint2, tos byte, n int) {
	c.tosMu.Lock()
	defer c.tosMu.Unlock()
	if c.tosCounts == nil {
		c.tosCounts = make(map[ChannelEndpoint2]map[byte]uint64)
	}
	m := c.tosCounts[remote]
	if m == nil {
		m = make(map[byte]uint64)
		c.tosCounts[remote] = m
	}
	m[tos] += uint64(n)
}

// TOSCounts returns a copy of the per-TOS outgoing packet counts recorded
// for dst (test seam for the outer DSCP marking path).
func (c *ChannelBind2) TOSCounts(dst ChannelEndpoint2) map[byte]uint64 {
	c.tosMu.Lock()
	defer c.tosMu.Unlock()
	m := c.tosCounts[dst]
	out := make(map[byte]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (c *ChannelBind2) send(bufs [][]byte, remote ChannelEndpoint2, hint uint16) error {
	for _, b := range bufs {
		select {
		case <-c.closeSignal:
			return net.ErrClosed
		default:
			bc := make([]byte, len(b))
			copy(bc, b)
			*c.tx <- chanPkt{
				data:    bc,
				remote:  remote,
				srcHint: hint,
			}
		}
	}
	return nil
}

func (c *ChannelBind2) Send(bufs [][]byte, ep conn.Endpoint) error {
	remote, hint := channelEndpointOf(ep)
	c.recordTOS(remote, 0, len(bufs))
	return c.send(bufs, remote, hint)
}

// SendTOS implements conn.TOSBind: a plain send with every datagram stamped
// tos, recorded per destination for test assertions.
func (c *ChannelBind2) SendTOS(bufs [][]byte, ep conn.Endpoint, tos byte) error {
	remote, hint := channelEndpointOf(ep)
	c.recordTOS(remote, tos, len(bufs))
	return c.send(bufs, remote, hint)
}

func (c *ChannelBind2) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return ChannelEndpoint2(ap), err
}
