package state

import (
	"fmt"

	"github.com/encodeous/nylon/polyamide/device"
)

// In-tunnel QoS: protocol/port rules from the config classify inner (tunnel)
// packets; matched flows are ordered first within in-device batches, and their
// outer (encapsulating) datagrams are stamped with the rule's DSCP so a
// DSCP-aware WAN bottleneck (tc at the edge, or any DSCP-aware path) can carry
// them past bulk transfers. See docs/guides/qos-priority.mdx and
// demo/qos-test.sh (the acceptance harness).

// Priority levels for priority_rules entries. The level sets both the
// in-device batch ordering (polyamide TCElement.Priority) and the default
// outer DSCP stamped on the encapsulating datagrams.
const (
	// PriorityMedium orders matched flows ahead of bulk within in-device
	// batches and stamps the outer packets with AF41 (DSCP 34).
	PriorityMedium = "medium"
	// PriorityHigh matches the nylon control plane's in-device level and
	// stamps the outer packets with EF (DSCP 46) — the expedited forwarding
	// codepoint a WAN edge (tc prio, or any EF queue) carries past a
	// saturated bulk queue.
	PriorityHigh = "high"
	// PriorityMax outranks everything, including the nylon control plane,
	// within in-device batches and stamps the outer packets with CS7
	// (DSCP 56).
	PriorityMax = "max"
)

// PriorityLevels lists the accepted priority_rules priority values.
func PriorityLevels() []string {
	return []string{PriorityMedium, PriorityHigh, PriorityMax}
}

// defaultPriorityDSCP maps a priority level to the outer DSCP (6-bit) stamped
// when the rule sets no explicit dscp override.
var defaultPriorityDSCP = map[string]int{
	PriorityMedium: 34, // AF41
	PriorityHigh:   46, // EF
	PriorityMax:    56, // CS7
}

// devicePriority maps a priority level to the in-device batch ordering level.
var devicePriority = map[string]device.TCPriority{
	PriorityMedium: device.TcMediumPriority,
	PriorityHigh:   device.TcHighPriority,
	PriorityMax:    device.TcMaxPriority,
}

// ruleProto maps a rule protocol name to the IPPROTO number the classifier
// matches on. The icmp entry (1) matches both ICMP (1) and ICMPv6 (58); the
// classifier normalises ICMPv6 to 1.
var ruleProto = map[string]byte{
	"icmp": 1,
	"tcp":  6,
	"udp":  17,
}

// MaxPriorityRules caps the number of priority_rules per source: the
// classifier scans the resolved list once per inner packet on the datapath.
const MaxPriorityRules = 64

// PortSpec is a single port ("5405") or an inclusive range ("5000-5100").
// Plain integers are accepted in YAML (`port: 5405` decodes as an int), so
// the field unmarshals both int and string scalars.
type PortSpec string

func (p *PortSpec) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v interface{}
	if err := unmarshal(&v); err != nil {
		return err
	}
	switch x := v.(type) {
	case nil:
		*p = ""
		return nil
	case int:
		*p = PortSpec(fmt.Sprintf("%d", x))
		return nil
	case uint64:
		*p = PortSpec(fmt.Sprintf("%d", x))
		return nil
	case string:
		*p = PortSpec(x)
		return nil
	default:
		return fmt.Errorf("port must be a port number or an inclusive range \"A-B\"")
	}
}

// PriorityRule classifies inner (tunnel) traffic by L4 protocol and port.
// Matched flows ride ahead of bulk traffic within in-device batches, and
// their outer (encapsulating) datagrams are stamped with the rule's DSCP so
// a DSCP-aware WAN path can prioritise the whole encrypted stream — the
// encrypted outer stream is otherwise indistinguishable, which is exactly
// what drowns small interactive flows at a saturated bottleneck today.
type PriorityRule struct {
	// Protocol is the inner L4 protocol to match: "tcp", "udp" or "icmp".
	Protocol string `yaml:"protocol"`
	// Port is the port (or inclusive range "A-B") to match on EITHER side
	// of the flow — the destination port of requests to the service and
	// the source port of its replies — e.g. "5405" for a corosync totem
	// port or "22" for ssh. Required for tcp/udp; icmp rules match all
	// ICMP traffic and must not set a port.
	Port PortSpec `yaml:"port,omitempty"`
	// Priority is the level to assign: "medium", "high" or "max". It sets
	// the in-device batch ordering and the default outer DSCP (AF41 / EF /
	// CS7 respectively). "normal" is not accepted — an unmarked rule is a
	// no-op and belongs out of the config.
	Priority string `yaml:"priority"`
	// Dscp optionally overrides the outer DSCP (0-63) stamped on matched
	// flows; the priority level's default (AF41/EF/CS7) applies when unset.
	// 0 keeps the in-device ordering but stamps nothing on the wire.
	Dscp *int `yaml:"dscp,omitempty"`
}

// ResolvedPriorityRule is the compiled, hot-path form of a PriorityRule.
type ResolvedPriorityRule struct {
	// Proto is the IPPROTO number to match (6 tcp, 17 udp, 1 icmp — the
	// latter matches both ICMP and ICMPv6).
	Proto byte
	// Ports is the inclusive port range to match on either flow side;
	// !Ports.Valid() matches every port (icmp rules).
	Ports PortRange
	// Prio is the in-device batch ordering level for matched flows.
	Prio device.TCPriority
	// TOS is the TOS byte stamped on the outer datagrams (DSCP << 2);
	// 0 marks nothing on the wire.
	TOS byte
}

// ValidatePriorityRules checks a rule list for internal consistency:
// known protocols, port presence per protocol (required for tcp/udp,
// forbidden for icmp), valid priority levels and DSCP overrides, and no
// exact duplicates. where names the config location for error messages.
func ValidatePriorityRules(rules []PriorityRule, where string) error {
	if len(rules) == 0 {
		return nil
	}
	if len(rules) > MaxPriorityRules {
		return fmt.Errorf("%s: priority_rules lists %d rules, at most %d are supported (the classifier scans the list per inner packet)", where, len(rules), MaxPriorityRules)
	}
	type ruleKey struct {
		proto byte
		ports PortRange
	}
	seen := make(map[ruleKey]struct{}, len(rules))
	for i, r := range rules {
		proto, ok := ruleProto[r.Protocol]
		if !ok {
			return fmt.Errorf("%s: priority_rules[%d]: unknown protocol %q (want tcp, udp or icmp)", where, i, r.Protocol)
		}
		switch r.Protocol {
		case "icmp":
			if r.Port != "" {
				return fmt.Errorf("%s: priority_rules[%d]: icmp rules must not set a port — they match all ICMP traffic", where, i)
			}
		default:
			if r.Port == "" {
				return fmt.Errorf("%s: priority_rules[%d]: protocol %s requires a port (a port match on every flow would also prioritise bulk UDP/TCP transfers)", where, i, r.Protocol)
			}
		}
		var ports PortRange
		if r.Port != "" {
			var err error
			ports, err = ParsePortRange(string(r.Port))
			if err != nil {
				return fmt.Errorf("%s: priority_rules[%d]: %w", where, i, err)
			}
		}
		if r.Priority == "normal" || r.Priority == "" {
			return fmt.Errorf("%s: priority_rules[%d]: priority %q would change nothing — a rule exists to raise traffic above bulk; use medium, high or max", where, i, r.Priority)
		}
		if _, ok := devicePriority[r.Priority]; !ok {
			return fmt.Errorf("%s: priority_rules[%d]: unknown priority %q (want one of %v)", where, i, r.Priority, PriorityLevels())
		}
		if r.Dscp != nil && (*r.Dscp < 0 || *r.Dscp > 63) {
			return fmt.Errorf("%s: priority_rules[%d]: dscp must be a 6-bit codepoint 0-63, got %d (e.g. 46 for EF)", where, i, *r.Dscp)
		}
		key := ruleKey{proto: proto, ports: ports}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%s: priority_rules[%d]: duplicate rule (protocol %s, port %s) — overlapping ranges are allowed and match in order, exact duplicates are a config error", where, i, r.Protocol, r.Port)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// ResolvePriorityRules compiles the winning source's rule list. Like the hop
// policy, the rule set is atomic per source: a central routers[] entry with a
// NON-EMPTY priority_rules list wins wholesale over the central config's
// top-level priority_rules (the mesh-wide default), which wins wholesale
// over node.yaml's priority_rules; with no rules set anywhere none apply.
// An empty list is indistinguishable from an absent one at every level
// (configs roundtrip through yaml with omitempty, which drops empty lists)
// — clearing a node's local rules is therefore not expressible centrally,
// exactly like the hop policy. The second return names the winning source
// ("central", "central-global", "node" or "default") for the journal.
func ResolvePriorityRules(central *RouterCfg, global []PriorityRule, local *LocalCfg) ([]ResolvedPriorityRule, string, error) {
	var rules []PriorityRule
	source := "default"
	switch {
	case central != nil && len(central.PriorityRules) > 0:
		rules, source = central.PriorityRules, "central"
	case len(global) > 0:
		rules, source = global, "central-global"
	case local != nil && len(local.PriorityRules) > 0:
		rules, source = local.PriorityRules, "node"
	}
	if len(rules) == 0 {
		return nil, source, nil
	}
	// rules are validated at config load; re-check here so a rule list that
	// skipped validation (tests, programmatic applies) fails loudly instead
	// of silently misclassifying
	if err := ValidatePriorityRules(rules, source); err != nil {
		return nil, source, err
	}
	out := make([]ResolvedPriorityRule, 0, len(rules))
	for _, r := range rules {
		var ports PortRange
		if r.Port != "" {
			ports, _ = ParsePortRange(string(r.Port)) // validated above
		}
		dscp := defaultPriorityDSCP[r.Priority]
		if r.Dscp != nil {
			dscp = *r.Dscp
		}
		out = append(out, ResolvedPriorityRule{
			Proto: ruleProto[r.Protocol],
			Ports: ports,
			Prio:  devicePriority[r.Priority],
			TOS:   byte(dscp) << 2,
		})
	}
	return out, source, nil
}
