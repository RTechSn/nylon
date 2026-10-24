/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"time"
)

/* Specification constants */

const (
	RekeyAfterMessages      = (1 << 60)
	RejectAfterMessages     = (1 << 64) - (1 << 13) - 1
	RekeyAfterTime          = time.Second * 120
	RekeyAttemptTime        = time.Second * 90
	RekeyTimeout            = time.Second * 5
	MaxTimerHandshakes      = 90 / 5 /* RekeyAttemptTime / RekeyTimeout */
	RekeyTimeoutJitterMaxMs = 334
	RejectAfterTime         = time.Second * 180
	KeepaliveTimeout        = time.Second * 10
	CookieRefreshTime       = time.Second * 120
	HandshakeInitationRate  = time.Second / 50
	PaddingMultiple         = 16
	DefaultUdpWindow        = 500
)

const (
	MinMessageSize = MessageKeepaliveSize                  // minimum size of transport message (keepalive)
	MaxMessageSize = MaxSegmentSize                        // maximum size of transport message
	MaxContentSize = MaxSegmentSize - MessageTransportSize // maximum size of transport message content
)

/* Implementation constants */

const (
	UnderLoadAfterTime = time.Second // how long does the device remain under load after detected
	MaxPeers           = 1 << 16     // maximum number of configured peers
)

// ExtraPortReceiveBatchSize caps the receive batch used by the receive
// routines of range-listener sockets (port hopping, MultiBind extras).
// Every RoutineReceiveIncoming holds batch x MaxMessageSize bytes of pooled
// buffers for the lifetime of its socket; with the full IdealBatchSize a
// 4096-port range would pin tens of gigabytes of receive buffers alone.
// A range port only ever carries budget-bounded bursts per activation
// (one hop budget's worth of data, handshakes, keepalives, junk), so a small
// batch is functionally sufficient and keeps per-port memory at a fraction
// of a megabyte.
const ExtraPortReceiveBatchSize = 4
