//go:build linux

package conn

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// recvTOSListener opens a UDP listener with IP_RECVTOS (v4) /
// IPV6_RECVTCLASS (v6) enabled so the received TOS byte is delivered as a
// control message.
func recvTOSListener(t *testing.T, network string) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP(network, &net.UDPAddr{})
	if err != nil {
		t.Skipf("cannot listen on %s loopback: %v", network, err)
	}
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		if network == "udp6" {
			sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1)
		} else {
			sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
		}
	})
	if err != nil || sockErr != nil {
		t.Fatalf("enable RECVTOS/TCLASS: %v / %v", err, sockErr)
	}
	return c
}

// readTOS reads one datagram and returns its payload, the TOS byte from the
// control messages and the sender's address.
func readTOS(t *testing.T, c *net.UDPConn) (string, byte, *net.UDPAddr) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	oob := make([]byte, 128)
	n, oobn, _, src, err := c.ReadMsgUDP(buf, oob)
	if err != nil {
		t.Fatal(err)
	}
	tos := byte(0)
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		t.Fatalf("parse control messages: %v", err)
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_TOS:
			if len(m.Data) >= 1 {
				tos = m.Data[0]
			}
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_TCLASS:
			if len(m.Data) >= 4 {
				tos = byte(binary.NativeEndian.Uint32(m.Data))
			}
		}
	}
	return string(buf[:n]), tos, src
}

func TestStdNetBindSendTOSLoopbackV4(t *testing.T) {
	recv := recvTOSListener(t, "udp4")
	defer recv.Close()

	sender := NewStdNetBind().(*StdNetBind)
	var _ TOSBind = sender
	if _, _, err := sender.Open(0); err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	ep, err := sender.ParseEndpoint(recv.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	if err := sender.SendTOS([][]byte{[]byte("marked")}, ep, 0xb8); err != nil {
		t.Fatal(err)
	}
	if p, tos, _ := readTOS(t, recv); p != "marked" || tos != 0xb8 {
		t.Errorf("SendTOS: payload %q tos %#02x, want \"marked\" 0xb8", p, tos)
	}

	if err := sender.Send([][]byte{[]byte("plain")}, ep); err != nil {
		t.Fatal(err)
	}
	if p, tos, _ := readTOS(t, recv); p != "plain" || tos != 0 {
		t.Errorf("Send: payload %q tos %#02x, want \"plain\" 0x00", p, tos)
	}
}

func TestStdNetBindSendTOSLoopbackV6(t *testing.T) {
	recv := recvTOSListener(t, "udp6")
	defer recv.Close()

	sender := NewStdNetBind().(*StdNetBind)
	var _ TOSBind = sender
	if _, _, err := sender.Open(0); err != nil {
		t.Skipf("no v6 support: %v", err)
	}
	defer sender.Close()

	ep, err := sender.ParseEndpoint(recv.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	if err := sender.SendTOS([][]byte{[]byte("marked6")}, ep, 0xb8); err != nil {
		t.Fatal(err)
	}
	if p, tos, _ := readTOS(t, recv); p != "marked6" || tos != 0xb8 {
		t.Errorf("SendTOS v6: payload %q tos %#02x, want \"marked6\" 0xb8", p, tos)
	}
}

func TestTOSControlMessageLayout(t *testing.T) {
	// v4: IP_TOS, 1 byte of data
	v4 := tosControlMessage(0xb8, false)
	hdr, data, rest, err := unix.ParseOneSocketControlMessage(v4)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Errorf("v4 trailing bytes: %d", len(rest))
	}
	if hdr.Level != unix.IPPROTO_IP || hdr.Type != unix.IP_TOS || len(data) != 1 || data[0] != 0xb8 {
		t.Errorf("v4 cmsg: level=%d type=%d data=%v", hdr.Level, hdr.Type, data)
	}

	// v6: IPV6_TCLASS, 4-byte int
	v6 := tosControlMessage(0xb8, true)
	hdr, data, rest, err = unix.ParseOneSocketControlMessage(v6)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Errorf("v6 trailing bytes: %d", len(rest))
	}
	if hdr.Level != unix.IPPROTO_IPV6 || hdr.Type != unix.IPV6_TCLASS || len(data) != 4 {
		t.Fatalf("v6 cmsg: level=%d type=%d datalen=%d", hdr.Level, hdr.Type, len(data))
	}
	if v := binary.NativeEndian.Uint32(data); v != 0xb8 {
		t.Errorf("v6 tclass = %#x, want 0xb8", v)
	}
}

// TestMultiBindSendTOSRoutesByPortHint: SendTOS through a MultiBind with a
// tagged endpoint must originate from the tagged range port and carry the
// TOS byte — the port-hopping reply-symmetry path must not lose the marking.
func TestMultiBindSendTOSRoutesByPortHint(t *testing.T) {
	recvPrimary := recvTOSListener(t, "udp4")
	defer recvPrimary.Close()

	mb := NewMultiBind()
	var _ TOSBind = mb
	_, port, err := mb.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer mb.Close()

	// bind one extra range port for the tagged flow
	var extraPort uint16
	for p := uint16(32000); p < 32100; p++ {
		if p == port {
			continue
		}
		if _, err := mb.OpenRange(port, PortRange{First: p, Last: p}); err == nil {
			extraPort = p
			break
		}
	}
	if extraPort == 0 {
		t.Skip("no free port for the range listener")
	}

	prim := netip.MustParseAddrPort(recvPrimary.LocalAddr().String())
	tagged := &TaggedEndpoint{
		Endpoint:  &StdNetEndpoint{AddrPort: prim},
		localPort: extraPort,
	}
	if err := mb.SendTOS([][]byte{[]byte("viatag")}, tagged, 0xb8); err != nil {
		t.Fatal(err)
	}
	// The datagram must arrive at the destination carrying EF, originating
	// from the tagged extra port (the MultiBind routes through the socket
	// owning that port).
	p, tos, src := readTOS(t, recvPrimary)
	if p != "viatag" || tos != 0xb8 {
		t.Errorf("tagged SendTOS: payload %q tos %#02x, want \"viatag\" 0xb8", p, tos)
	}
	if src == nil || src.Port != int(extraPort) {
		t.Errorf("tagged SendTOS source port = %v, want %d", src, extraPort)
	}
}
