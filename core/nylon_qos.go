package core

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/state"
)

// in-tunnel QoS: the classifier (installed first in run order by InstallTC)
// stamps matching inner packets — protocol/port rules from the config, see
// state.PriorityRule — with the rule's in-device batch priority and outer
// TOS byte; the transport mirrors the TOS onto the encapsulating datagrams
// (conn.TOSBind.SendTOS). The encrypted outer stream is otherwise
// indistinguishable, which is exactly what drowns small interactive flows
// (ssh, a corosync totem ring) when a bulk transfer saturates the WAN
// bottleneck — see demo/qos-test.sh, the acceptance harness.

// l4Flow extracts the L4 protocol and, for TCP/UDP, the source and
// destination ports from an inner IP packet b. The returned proto is the
// IPPROTO number, with ICMPv6 (58) normalised to icmp (1) — rule-level icmp
// matches both. ok=false: nothing to classify (poly protocol, truncated, a
// non-first IPv4 fragment whose offset hides the L4 header, or an IPv6
// packet with extension headers before the L4 one).
func l4Flow(b []byte) (proto byte, sport, dport uint16, ok bool) {
	if len(b) == 0 {
		return 0, 0, 0, false
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return 0, 0, 0, false
		}
		// non-first fragments carry no L4 header to match on
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return 0, 0, 0, false
		}
		ihl := int(b[0]&0xf) * 4
		if ihl < 20 || len(b) < ihl+4 {
			return 0, 0, 0, false
		}
		switch b[9] {
		case 6, 17: // tcp, udp
			return b[9], binary.BigEndian.Uint16(b[ihl:]), binary.BigEndian.Uint16(b[ihl+2:]), true
		case 1: // icmp
			return 1, 0, 0, true
		}
		return 0, 0, 0, false
	case 6:
		if len(b) < 40 {
			return 0, 0, 0, false
		}
		switch b[6] { // next header; extension headers are not classified
		case 6, 17:
			if len(b) < 44 {
				return 0, 0, 0, false
			}
			return b[6], binary.BigEndian.Uint16(b[40:]), binary.BigEndian.Uint16(b[42:]), true
		case 58: // icmpv6
			return 1, 0, 0, true
		}
		return 0, 0, 0, false
	}
	return 0, 0, 0, false
}

// classifyPriority applies the resolved rule set to an element: the first
// matching rule sets the in-device batch priority and the outer TOS byte.
// Runs on the TC hot path; with no rules configured it is a single atomic
// load.
func (n *Nylon) classifyPriority(elem *device.TCElement) {
	rules := n.priorityRules.Load()
	if rules == nil || len(*rules) == 0 {
		return
	}
	proto, sport, dport, ok := l4Flow(elem.Packet)
	if !ok {
		return
	}
	for i := range *rules {
		r := &(*rules)[i]
		if r.Proto != proto {
			continue
		}
		// the port matches on either side of the flow: the dport of
		// requests to the service and the sport of its replies
		if r.Ports.Valid() && !r.Ports.Contains(sport) && !r.Ports.Contains(dport) {
			continue
		}
		elem.Priority = r.Prio
		elem.TOS = r.TOS
		return
	}
}

// ensurePriorityRules resolves the effective in-tunnel QoS rule set — a
// central router entry with priority_rules set wins wholesale over
// node.yaml, which wins over none (state.ResolvePriorityRules) — and
// publishes it to the classifier. Runs on the dispatch loop from
// SyncApplicationState: immediately at start and after every config apply.
func (n *Nylon) ensurePriorityRules() error {
	if n.Device == nil {
		return nil
	}
	var rc *state.RouterCfg
	if n.CentralCfg.IsRouter(n.LocalCfg.Id) {
		router := n.CentralCfg.GetRouter(n.LocalCfg.Id)
		rc = &router
	}
	rules, source, err := state.ResolvePriorityRules(rc, &n.LocalCfg)
	if err != nil {
		return fmt.Errorf("priority rules: %w", err)
	}
	if sig := priorityRulesSignature(rules); sig != n.priorityRulesSig {
		n.priorityRulesSig = sig
		if len(rules) == 0 {
			n.Log.Info("priority rules cleared", "source", source)
		} else {
			n.Log.Info("priority rules applied", "rules", len(rules), "source", source, "detail", sig)
		}
		if len(rules) > 0 {
			if _, ok := n.Device.Bind().(conn.TOSBind); !ok {
				n.Log.Warn("outer DSCP marking is not supported by this platform's bind; the priority rules apply to in-device batch ordering only")
			}
		}
	}
	n.priorityRules.Store(&rules)
	return nil
}

// priorityRulesSignature renders a human-readable, change-detection
// signature of a resolved rule set, e.g. "udp/5405=high:0xb8;tcp/22=high:0xb8".
func priorityRulesSignature(rules []state.ResolvedPriorityRule) string {
	var sb strings.Builder
	for i := range rules {
		if i > 0 {
			sb.WriteByte(';')
		}
		fmt.Fprintf(&sb, "%s/%s=%s:%#02x", ruleProtoName(rules[i].Proto), rules[i].Ports, rulePrioName(rules[i].Prio), rules[i].TOS)
	}
	return sb.String()
}

func ruleProtoName(p byte) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	}
	return fmt.Sprintf("proto%d", p)
}

func rulePrioName(p device.TCPriority) string {
	switch p {
	case device.TcMediumPriority:
		return "medium"
	case device.TcHighPriority:
		return "high"
	case device.TcMaxPriority:
		return "max"
	}
	return fmt.Sprintf("prio%d", p)
}
