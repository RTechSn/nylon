//go:build linux || android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// tosControlSize is the control-message space needed to stamp one IPv4
// IP_TOS / IPv6 IPV6_TCLASS value on an outgoing datagram (per-packet DSCP
// marking of the outer stream; see TOSBind).
var tosControlSize = unix.CmsgSpace(4)

// tosControlMessage renders the control message carrying tos on the outer
// datagrams: IP_TOS (1 byte) for IPv4 destinations, IPV6_TCLASS (a 4-byte
// int in host byte order, per RFC 3542 / the Linux cmsg parser) for IPv6.
func tosControlMessage(tos byte, is6 bool) []byte {
	if is6 {
		buf := make([]byte, unix.CmsgSpace(4))
		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&buf[0]))
		hdr.Level = unix.IPPROTO_IPV6
		hdr.Type = unix.IPV6_TCLASS
		hdr.Len = uint64(unix.CmsgLen(4))
		*(*int32)(unsafe.Pointer(&buf[unix.CmsgLen(0)])) = int32(tos)
		return buf
	}
	buf := make([]byte, unix.CmsgSpace(1))
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&buf[0]))
	hdr.Level = unix.IPPROTO_IP
	hdr.Type = unix.IP_TOS
	hdr.Len = uint64(unix.CmsgLen(1))
	buf[unix.CmsgLen(0)] = tos
	return buf
}

// appendTOSControl appends a rendered TOS control message to control. The
// pooled OOB buffers are sized for the sticky source plus GSO plus one TOS
// message, so the append is allocation-free in practice.
func appendTOSControl(control *[]byte, tosCtl []byte) {
	*control = append(*control, tosCtl...)
}

// SendTOS implements TOSBind: like Send, but every datagram of bufs carries
// tos as its IPv4 Type-of-Service / IPv6 Traffic Class byte.
func (s *StdNetBind) SendTOS(bufs [][]byte, endpoint Endpoint, tos byte) error {
	return s.sendDatagrams(bufs, endpoint, tos)
}

// SendTOS implements TOSBind for MultiBind, routing through the same
// per-port socket Send would use (port-hopping reply symmetry) and stamping
// tos on the outer datagrams.
func (b *MultiBind) SendTOS(bufs [][]byte, endpoint Endpoint, tos byte) error {
	sb, ep := b.bindForSend(endpoint)
	return sb.SendTOS(bufs, ep, tos)
}
