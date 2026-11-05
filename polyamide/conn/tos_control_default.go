//go:build !linux && !android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

// tosControlSize is zero on platforms without sendmsg control-message TOS
// support (macOS, Windows): those platforms do not implement TOSBind at all,
// so callers fall back to an unmarked Send. The stubs below keep
// sendDatagrams portable; with no SendTOS entry point they can never run
// with tos != 0.
const tosControlSize = 0

func tosControlMessage(tos byte, is6 bool) []byte { return nil }

func appendTOSControl(*[]byte, []byte) {}
