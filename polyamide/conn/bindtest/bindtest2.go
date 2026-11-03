/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package bindtest

import (
	"github.com/encodeous/nylon/polyamide/conn"
	"net"
	"net/netip"
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

func (c *ChannelBind2) Send(bufs [][]byte, ep conn.Endpoint) error {
	var remote ChannelEndpoint2
	var hint uint16
	switch e := ep.(type) {
	case ChannelEndpoint2:
		remote = e
	case HintedEndpoint:
		remote, hint = e.Dst, e.SrcPort
	default:
		// hinted endpoint types from other packages (e.g. the real
		// conn.TaggedEndpoint): unwrap the destination, carry the port hint
		ap := ep.DstIPPort()
		remote = ChannelEndpoint2(ap)
		if h, ok := ep.(interface{ PortHint() uint16 }); ok {
			hint = h.PortHint()
		}
	}
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

func (c *ChannelBind2) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return ChannelEndpoint2(ap), err
}
