package core

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/state"
)

// v4Packet builds a minimal IPv4 packet carrying the given L4 bytes. An
// optional frag argument sets the IPv4 fragment field.
func v4Packet(t *testing.T, proto byte, src, dst netip.Addr, l4 []byte, frag ...uint16) []byte {
	t.Helper()
	total := 20 + len(l4)
	b := make([]byte, total)
	b[0] = 0x45 // v4, IHL 5
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	if len(frag) > 0 {
		binary.BigEndian.PutUint16(b[6:8], frag[0])
	}
	b[8] = 64 // ttl
	b[9] = proto
	sb, _ := src.MarshalBinary()
	db, _ := dst.MarshalBinary()
	copy(b[12:16], sb)
	copy(b[16:20], db)
	copy(b[20:], l4)
	return b
}

// v6Packet builds a minimal IPv6 packet carrying the given L4 bytes.
func v6Packet(t *testing.T, nextHeader byte, src, dst netip.Addr, l4 []byte) []byte {
	t.Helper()
	total := 40 + len(l4)
	b := make([]byte, total)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(total-40))
	b[6] = nextHeader
	b[7] = 64
	sb, _ := src.MarshalBinary()
	db, _ := dst.MarshalBinary()
	copy(b[8:24], sb)
	copy(b[24:40], db)
	copy(b[40:], l4)
	return b
}

// tcpPorts renders a TCP header prefix with the given ports.
func tcpPorts(sport, dport uint16) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	return b
}

// udpPorts renders a UDP header prefix with the given ports.
func udpPorts(sport, dport uint16, payloadLen int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint16(b[4:6], uint16(8+payloadLen))
	return b
}

var (
	qa = netip.MustParseAddr("10.1.0.1")
	qb = netip.MustParseAddr("10.1.0.2")
	q6 = netip.MustParseAddr("fd00::1")
)

func TestL4Flow(t *testing.T) {
	cases := []struct {
		name         string
		b            []byte
		proto        byte
		sport, dport uint16
		ok           bool
	}{
		{"v4 tcp", v4Packet(t, 6, qa, qb, tcpPorts(40000, 22)), 6, 40000, 22, true},
		{"v4 udp", v4Packet(t, 17, qa, qb, udpPorts(40000, 5405, 1)), 17, 40000, 5405, true},
		{"v4 icmp", v4Packet(t, 1, qa, qb, []byte{8, 0, 0, 0}), 1, 0, 0, true},
		{"v4 ihl beyond packet", func() []byte {
			b := v4Packet(t, 6, qa, qb, tcpPorts(1, 2))
			b[0] = 0x46 // IHL 6 claims a 24-byte header
			return b[:22]
		}(), 0, 0, 0, false},
		{"v4 non-first fragment", v4Packet(t, 6, qa, qb, tcpPorts(1, 2), 0x0008), 0, 0, 0, false},
		{"v4 first fragment (mf set)", func() []byte {
			b := v4Packet(t, 6, qa, qb, tcpPorts(40000, 22))
			binary.BigEndian.PutUint16(b[6:8], 0x2000) // MF, offset 0
			return b
		}(), 6, 40000, 22, true},
		{"v4 other proto", v4Packet(t, 47, qa, qb, []byte{1, 2, 3, 4}), 0, 0, 0, false},
		{"v4 truncated l4", v4Packet(t, 6, qa, qb, []byte{1, 2, 3})[:22], 0, 0, 0, false},
		{"v6 tcp", v6Packet(t, 6, q6, q6, tcpPorts(40000, 22)), 6, 40000, 22, true},
		{"v6 udp", v6Packet(t, 17, q6, q6, udpPorts(40000, 5405, 1)), 17, 40000, 5405, true},
		{"v6 icmpv6", v6Packet(t, 58, q6, q6, []byte{128, 0, 0, 0}), 1, 0, 0, true},
		{"v6 ext header", v6Packet(t, 0, q6, q6, []byte{1, 2, 3, 4}), 0, 0, 0, false},
		{"v6 truncated", v6Packet(t, 6, q6, q6, tcpPorts(1, 2))[:42], 0, 0, 0, false},
		{"poly protocol", func() []byte { b := make([]byte, 16); b[0] = 8 << 4; return b }(), 0, 0, 0, false},
		{"empty", nil, 0, 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proto, sport, dport, ok := l4Flow(tc.b)
			if ok != tc.ok || (ok && (proto != tc.proto || sport != tc.sport || dport != tc.dport)) {
				t.Errorf("l4Flow = (%d, %d, %d, %v), want (%d, %d, %d, %v)",
					proto, sport, dport, ok, tc.proto, tc.sport, tc.dport, tc.ok)
			}
		})
	}
}

func storeRules(n *Nylon, rules []state.ResolvedPriorityRule) {
	n.priorityRules.Store(&rules)
}

func TestClassifyPriority(t *testing.T) {
	n := &Nylon{}

	// no rules: untouched, single atomic load
	elem := &device.TCElement{Packet: v4Packet(t, 6, qa, qb, tcpPorts(40000, 22))}
	n.classifyPriority(elem)
	if elem.Priority != 0 || elem.TOS != 0 {
		t.Fatalf("no rules: priority=%d tos=%#02x, want untouched", elem.Priority, elem.TOS)
	}

	udpHigh := state.ResolvedPriorityRule{Proto: 17, Ports: state.PortRange{First: 5405, Last: 5405}, Prio: device.TcHighPriority, TOS: 0xb8}
	sshHigh := state.ResolvedPriorityRule{Proto: 6, Ports: state.PortRange{First: 22, Last: 22}, Prio: device.TcHighPriority, TOS: 0xb8}
	tcpMediumRange := state.ResolvedPriorityRule{Proto: 6, Ports: state.PortRange{First: 5000, Last: 5100}, Prio: device.TcMediumPriority, TOS: 0x88}
	icmpMax := state.ResolvedPriorityRule{Proto: 1, Prio: device.TcMaxPriority, TOS: 0xe0}
	storeRules(n, []state.ResolvedPriorityRule{udpHigh, sshHigh, tcpMediumRange, icmpMax})

	cases := []struct {
		name string
		b    []byte
		prio device.TCPriority
		tos  byte
	}{
		{"udp dport 5405", v4Packet(t, 17, qa, qb, udpPorts(40000, 5405, 1)), device.TcHighPriority, 0xb8},
		{"udp sport 5405 (reply side)", v4Packet(t, 17, qa, qb, udpPorts(5405, 40000, 1)), device.TcHighPriority, 0xb8},
		{"udp unmatched", v4Packet(t, 17, qa, qb, udpPorts(40000, 7999, 1)), 0, 0},
		{"tcp dport 22", v4Packet(t, 6, qa, qb, tcpPorts(40000, 22)), device.TcHighPriority, 0xb8},
		{"tcp sport 22 (reply side)", v4Packet(t, 6, qa, qb, tcpPorts(22, 40000)), device.TcHighPriority, 0xb8},
		{"tcp range 5050", v4Packet(t, 6, qa, qb, tcpPorts(40000, 5050)), device.TcMediumPriority, 0x88},
		{"tcp unmatched", v4Packet(t, 6, qa, qb, tcpPorts(40000, 443)), 0, 0},
		{"icmp v4", v4Packet(t, 1, qa, qb, []byte{8, 0, 0, 0}), device.TcMaxPriority, 0xe0},
		{"icmpv6", v6Packet(t, 58, q6, q6, []byte{128, 0, 0, 0}), device.TcMaxPriority, 0xe0},
		{"v6 tcp 22", v6Packet(t, 6, q6, q6, tcpPorts(40000, 22)), device.TcHighPriority, 0xb8},
		{"v4 fragment", func() []byte {
			b := v4Packet(t, 17, qa, qb, udpPorts(40000, 5405, 1))
			binary.BigEndian.PutUint16(b[6:8], 0x2008) // non-first fragment
			return b
		}(), 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			elem := &device.TCElement{Packet: tc.b}
			n.classifyPriority(elem)
			if elem.Priority != tc.prio || elem.TOS != tc.tos {
				t.Errorf("classify = (prio %d, tos %#02x), want (%d, %#02x)", elem.Priority, elem.TOS, tc.prio, tc.tos)
			}
		})
	}
}

// TestClassifyPriorityFirstMatchWins: with overlapping rules the FIRST
// matching rule wins (documented scan order).
func TestClassifyPriorityFirstMatchWins(t *testing.T) {
	n := &Nylon{}
	wide := state.ResolvedPriorityRule{Proto: 6, Ports: state.PortRange{First: 5000, Last: 5100}, Prio: device.TcMediumPriority, TOS: 0x88}
	narrow := state.ResolvedPriorityRule{Proto: 6, Ports: state.PortRange{First: 5050, Last: 5050}, Prio: device.TcMaxPriority, TOS: 0xe0}
	storeRules(n, []state.ResolvedPriorityRule{wide, narrow})
	elem := &device.TCElement{Packet: v4Packet(t, 6, qa, qb, tcpPorts(40000, 5050))}
	n.classifyPriority(elem)
	if elem.Priority != device.TcMediumPriority || elem.TOS != 0x88 {
		t.Errorf("first match lost: prio=%d tos=%#02x", elem.Priority, elem.TOS)
	}
}

// TestClassifyPriorityNilRules: a nil rule-set pointer (before the first
// ensurePriorityRules pass) must be a no-op.
func TestClassifyPriorityNilRules(t *testing.T) {
	n := &Nylon{}
	elem := &device.TCElement{Packet: v4Packet(t, 17, qa, qb, udpPorts(40000, 5405, 1))}
	n.classifyPriority(elem)
	if elem.Priority != 0 || elem.TOS != 0 {
		t.Errorf("nil rules touched the element: prio=%d tos=%#02x", elem.Priority, elem.TOS)
	}
}
