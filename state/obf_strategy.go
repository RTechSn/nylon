package state

import (
	"fmt"
	"slices"
	"strings"
)

// The obf strategy model (config reform):
//
//      obf:                      # central top level — named strategies, mesh-wide
//        awg_main:
//          protocol: quic        # informational: amnezigo template the i-params were drawn from
//          ports: "40000"        # required: one port or an inclusive range "40000-50000"
//          i1: ... i5: ...       # optional sender junk packets (see the note below)
//        hopping:
//          ports: "40000-50000"
//          port_hopping_mode: timed     # rotation policy moved INTO the strategy
//          port_hopping:
//            period_seconds: 30
//        vanilla:
//          ports: "51820"
//
//      routers:
//        - id: hub
//          endpoints:
//            - hub.example.com[hopping,vanilla]   # per-endpoint strategy selection
//            - 203.0.113.7[awg_main]
//            - 198.51.100.9:51820                # raw fixed-port endpoint (no strategy)
//
// Ports therefore live in strategies; the listen half of a node binds the
// union of ports over the strategies its OWN advertised endpoints name
// (untagged / "[*]" = all strategies), and the connect half expands every
// tagged peer endpoint into one candidate set per named strategy.
//
// WIRE REALITY (documented, not negotiable by config): the AWG 2.0 device
// speaks exactly ONE dialect. The S/H/J profile is mesh-wide (awg_profile),
// and the I-packet set is device-global: I-packets are prepended to every
// handshake toward EVERY peer. A strategy's i1..i5 therefore apply to a
// node's handshakes toward all peers, not only toward peers reached via that
// strategy — and the strategies a node uses must agree on one i-set. See
// EffectiveStrategyIPackets.

// ObfStrategy is one named entry of the central top-level `obf` map: a
// wire-reachability definition (ports) plus, optionally, the client-side
// rotation policy for those ports and the sender junk packets to emit.
type ObfStrategy struct {
	Protocol string `yaml:"protocol,omitempty"` // informational label (amnezigo template provenance); no runtime effect

	// Ports is the strategy's port spec: a single port ("40000") or an
	// inclusive range ("40000-50000"). Required.
	Ports string `yaml:"ports"`

	// Client-side rotation policy for the strategy's ports (when the mode
	// governs rotation of the carrying endpoint drawn from this strategy).
	PortHoppingMode string          `yaml:"port_hopping_mode,omitempty"` // static (default) | reactive | proactive | timed
	PortHopping     *PortHoppingCfg `yaml:"port_hopping,omitempty"`

	// Sender-local junk packets (AWG I1-I5). At most one i-set may be in
	// effect per node: the strategies the node uses must define identical
	// non-empty i-params (see EffectiveStrategyIPackets).
	I1 string `yaml:"i1,omitempty"`
	I2 string `yaml:"i2,omitempty"`
	I3 string `yaml:"i3,omitempty"`
	I4 string `yaml:"i4,omitempty"`
	I5 string `yaml:"i5,omitempty"`
}

// iParams returns the strategy's I-packet specs in wire order.
func (s *ObfStrategy) iParams() [5]string {
	if s == nil {
		return [5]string{}
	}
	return [5]string{s.I1, s.I2, s.I3, s.I4, s.I5}
}

// ipParamsSet reports whether the strategy defines any I-packet.
func (s *ObfStrategy) iParamsSet() bool {
	for _, v := range s.iParams() {
		if v != "" {
			return true
		}
	}
	return false
}

// hopPolicySignature renders a strategy's rotation policy for change
// detection (journal + wire-up comparisons).
func (s *ObfStrategy) HopPolicySignature() string {
	p := s.PortHopping.Resolve()
	p.Mode = s.PortHoppingMode
	if p.Mode == "" {
		p.Mode = HopModeStatic
	}
	return fmt.Sprintf("%s|%d|%s|%d|%s|%s", p.Mode, p.Budget, p.Period, p.JitterPct, p.RecycleMinInterval, p.Cooldown)
}

// StrategyNames returns the strategy map's names in stable (sorted) order.
func StrategyNames(m map[string]*ObfStrategy) []string {
	out := make([]string, 0, len(m))
	for name := range m {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// ParseStrategyPorts parses a strategy's ports spec into a PortRange.
func ParseStrategyPorts(s *ObfStrategy, name string) (PortRange, error) {
	if s == nil || strings.TrimSpace(s.Ports) == "" {
		return PortRange{}, fmt.Errorf("obf strategy %s: ports is required (a single port or an inclusive range, e.g. \"40000\" or \"40000-50000\")", name)
	}
	pr, err := ParsePortRange(strings.TrimSpace(s.Ports))
	if err != nil {
		return PortRange{}, fmt.Errorf("obf strategy %s: ports: %w", name, err)
	}
	return pr, nil
}

// ResolveStrategyHopPolicy resolves one strategy's rotation policy with the
// built-in defaults. The mode defaults to static.
func ResolveStrategyHopPolicy(s *ObfStrategy) PortHoppingPolicy {
	p := DefaultPortHoppingPolicy()
	if s == nil {
		return p
	}
	p = s.PortHopping.Resolve()
	p.Mode = s.PortHoppingMode
	if p.Mode == "" {
		p.Mode = HopModeStatic
	}
	return p
}

// StrategyPortRangeOf returns the parsed ports of a named strategy.
func StrategyPortRangeOf(m map[string]*ObfStrategy, name string) (PortRange, error) {
	s, ok := m[name]
	if !ok {
		return PortRange{}, fmt.Errorf("unknown obf strategy %q", name)
	}
	return ParseStrategyPorts(s, name)
}

// EndpointStrategyTags expands an endpoint's strategy tag list into concrete
// strategy names. An untagged endpoint (or the "*" wildcard) means "all
// strategies defined in the mesh": the default is everything available. A
// concrete tag that names no defined strategy is a config error.
func EndpointStrategyTags(spec EndpointSpec, m map[string]*ObfStrategy) ([]string, error) {
	all := StrategyNames(m)
	for _, tag := range spec.Strategies {
		if tag == "*" {
			return all, nil
		}
	}
	if len(spec.Strategies) == 0 {
		return all, nil
	}
	out := make([]string, 0, len(spec.Strategies))
	for _, tag := range spec.Strategies {
		if _, ok := m[tag]; !ok {
			return nil, fmt.Errorf("endpoint %s references undefined obf strategy %q (defined: %v)", spec.String(), tag, all)
		}
		out = append(out, tag)
	}
	slices.Sort(out)
	return out, nil
}

// ListenUnionRanges derives a node's listen half from its advertised
// endpoints: the union of ports over every strategy the node's own endpoints
// name (untagged = all strategies), merged into a minimal set of disjoint
// inclusive ranges. The primary port (node.yaml port) is always bound by the
// device itself and is NOT part of this union.
//
// A node with no advertised endpoints serves no strategies (clients accept
// no inbound connections); an empty strategy map yields no ranges.
func ListenUnionRanges(router *RouterCfg, m map[string]*ObfStrategy) ([]PortRange, error) {
	var names []string
	seen := map[string]struct{}{}
	add := func(list []string) {
		for _, n := range list {
			if _, ok := seen[n]; !ok {
				seen[n] = struct{}{}
				names = append(names, n)
			}
		}
	}
	if router != nil {
		for _, addr := range router.Endpoints {
			spec, err := ParseEndpointSpec(addr)
			if err != nil {
				// unreachable via validation (CentralConfigValidator parses
				// every endpoint); a broken spec simply contributes nothing
				continue
			}
			// tagged and bare-host endpoints contribute (untagged = all
			// strategies); raw host:port endpoints never do
			if !spec.HasStrategies() && (spec.Ports.Valid() || len(m) == 0) {
				continue
			}
			tags, err := EndpointStrategyTags(spec, m)
			if err != nil {
				return nil, err
			}
			add(tags)
		}
	}
	var prs []PortRange
	for _, name := range names {
		pr, err := StrategyPortRangeOf(m, name)
		if err != nil {
			return nil, err
		}
		prs = append(prs, pr)
	}
	return MergePortRanges(prs...), nil
}

// MergePortRanges folds a list of inclusive port ranges into a minimal set
// of disjoint ranges (sorted, overlapping/adjacent ranges coalesced). Used
// both for the listen union and for rendering the device UAPI form.
func MergePortRanges(prs ...PortRange) []PortRange {
	var valid []PortRange
	for _, pr := range prs {
		if pr.Valid() {
			valid = append(valid, pr)
		}
	}
	if len(valid) == 0 {
		return nil
	}
	slices.SortFunc(valid, func(a, b PortRange) int {
		if a.First != b.First {
			return int(a.First) - int(b.First)
		}
		return int(a.Last) - int(b.Last)
	})
	out := []PortRange{valid[0]}
	for _, pr := range valid[1:] {
		last := &out[len(out)-1]
		if pr.First <= last.Last || pr.First == last.Last+1 {
			if pr.Last > last.Last {
				last.Last = pr.Last
			}
			continue
		}
		out = append(out, pr)
	}
	return out
}

// EffectiveStrategyIPackets resolves the junk-packet set a node's device must
// speak, given the strategies the node uses (union over the strategy tags of
// its own and its peers' advertised endpoints). The AWG 2.0 device prepends
// the I-packets to every handshake toward every peer, so at most one i-set
// may be in effect: all used strategies with a non-empty i-set must define
// the SAME one. Returns the effective specs and the name of the strategy that
// provided them ("" when the node speaks no junk).
func EffectiveStrategyIPackets(m map[string]*ObfStrategy, used []string) ([5]string, string, error) {
	var zero [5]string
	var effective [5]string
	source := ""
	for _, name := range used {
		s, ok := m[name]
		if !ok || !s.iParamsSet() {
			continue
		}
		set := s.iParams()
		if source == "" {
			effective = set
			source = name
			continue
		}
		if set != effective {
			return zero, "", fmt.Errorf("obf strategies %s and %s define different i1..i5, but the AWG 2.0 device emits one junk-packet set on every handshake toward every peer; strategies used by the same node must share a single i-set (or leave the i-params unset in all but one of them)", source, name)
		}
	}
	return effective, source, nil
}

// NodeUsedStrategies computes the strategies a node may speak, in stable
// order: every strategy named by its own advertised endpoints (the listen
// half) or by any router's advertised endpoints (the connect half — a
// conservative superset of the node's actual neighbours, so a graph change
// can never make a previously-valid config start failing at runtime without
// having been re-sealed). Untagged endpoints expand to all strategies.
func NodeUsedStrategies(central *CentralCfg, node NodeId) []string {
	if central == nil {
		return nil
	}
	m := central.ObfStrategies
	if len(m) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(list []string) {
		for _, n := range list {
			if _, ok := seen[n]; !ok {
				seen[n] = struct{}{}
				out = append(out, n)
			}
		}
	}
	for i := range central.Routers {
		r := &central.Routers[i]
		for _, addr := range r.Endpoints {
			spec, err := ParseEndpointSpec(addr)
			if err != nil {
				continue
			}
			// tagged and bare-host endpoints contribute (untagged expands
			// to all strategies via EndpointStrategyTags); raw
			// host:port endpoints never do
			if !spec.HasStrategies() && (spec.Ports.Valid() || len(m) == 0) {
				continue
			}
			tags, err := EndpointStrategyTags(spec, m)
			if err != nil {
				continue
			}
			add(tags)
		}
	}
	slices.Sort(out)
	return out
}

// ValidateObfStrategies checks the central strategy map: names, ports,
// per-strategy rotation policy, and the i-set coherence across every
// strategy any endpoint may name.
func ValidateObfStrategies(cfg *CentralCfg) error {
	m := cfg.ObfStrategies
	if len(m) == 0 {
		return nil
	}
	for _, name := range StrategyNames(m) {
		s := m[name]
		if err := NameValidator(name); err != nil {
			return fmt.Errorf("obf strategy name: %w", err)
		}
		if _, err := ParseStrategyPorts(s, name); err != nil {
			return err
		}
		if err := ValidateHopPolicyCfg(s.PortHoppingMode, s.PortHopping, fmt.Sprintf("obf strategy %s", name)); err != nil {
			return err
		}
	}
	// The mesh-wide coherence check: the superset of every strategy named by
	// any endpoint must share one i-set, so `nylon seal` / `nylon verify`
	// give one consistent answer. NodeConfigValidator re-checks the node's
	// own used set (defense in depth).
	var used []string
	seen := map[string]struct{}{}
	for i := range cfg.Routers {
		for _, addr := range cfg.Routers[i].Endpoints {
			spec, err := ParseEndpointSpec(addr)
			if err != nil || !spec.HasStrategies() {
				// unparseable endpoints are reported by the router loop with
				// node context; here they contribute no strategies
				continue
			}
			tags, err := EndpointStrategyTags(spec, m)
			if err != nil {
				return err
			}
			for _, t := range tags {
				if _, ok := seen[t]; !ok {
					seen[t] = struct{}{}
					used = append(used, t)
				}
			}
		}
	}
	slices.Sort(used)
	if _, _, err := EffectiveStrategyIPackets(m, used); err != nil {
		return err
	}
	return nil
}

// formatRanges renders a range list for messages and journals:
// "40000-50000,51820".
func formatRanges(prs []PortRange) string {
	parts := make([]string, 0, len(prs))
	for _, pr := range prs {
		parts = append(parts, pr.String())
	}
	return strings.Join(parts, ",")
}

// RangesString is the exported form of formatRanges (device UAPI rendering,
// journal lines).
func RangesString(prs []PortRange) string {
	return formatRanges(prs)
}
