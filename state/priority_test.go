package state

import (
	"strings"
	"testing"

	"github.com/encodeous/nylon/polyamide/device"
	"github.com/goccy/go-yaml"
)

func dscpPtr(v int) *int { return &v }

func TestPriorityRuleYamlRoundtrip(t *testing.T) {
	src := `
priority_rules:
  - protocol: udp
    port: 5405
    priority: high
  - protocol: tcp
    port: 22
    priority: high
  - protocol: tcp
    port: "5000-5100"
    priority: medium
    dscp: 34
  - protocol: icmp
    priority: max
`
	var local LocalCfg
	if err := unmarshalT(t, src, &local); err != nil {
		t.Fatal(err)
	}
	want := []PriorityRule{
		{Protocol: "udp", Port: "5405", Priority: PriorityHigh},
		{Protocol: "tcp", Port: "22", Priority: PriorityHigh},
		{Protocol: "tcp", Port: "5000-5100", Priority: PriorityMedium, Dscp: dscpPtr(34)},
		{Protocol: "icmp", Priority: PriorityMax},
	}
	if len(local.PriorityRules) != len(want) {
		t.Fatalf("got %d rules, want %d: %+v", len(local.PriorityRules), len(want), local.PriorityRules)
	}
	for i, r := range want {
		got := local.PriorityRules[i]
		if got.Protocol != r.Protocol || got.Port != r.Port || got.Priority != r.Priority {
			t.Errorf("rule %d: got %+v, want %+v", i, got, r)
		}
		switch {
		case got.Dscp == nil && r.Dscp != nil, got.Dscp != nil && r.Dscp == nil:
			t.Errorf("rule %d: dscp presence mismatch: %v vs %v", i, got.Dscp, r.Dscp)
		case got.Dscp != nil && *got.Dscp != *r.Dscp:
			t.Errorf("rule %d: dscp = %d, want %d", i, *got.Dscp, *r.Dscp)
		}
	}

	// central side: the router's own entry AND the mesh-wide top-level list
	csrc := `
routers:
  - id: n1
    pubkey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    priority_rules:
      - protocol: udp
        port: 5405
        priority: high
priority_rules:
  - protocol: tcp
    port: 22
    priority: max
`
	var central CentralCfg
	if err := unmarshalT(t, csrc, &central); err != nil {
		t.Fatal(err)
	}
	if len(central.Routers) != 1 || len(central.Routers[0].PriorityRules) != 1 {
		t.Fatalf("central parse: %+v", central)
	}
	if got := central.Routers[0].PriorityRules[0]; got.Protocol != "udp" || got.Port != "5405" || got.Priority != PriorityHigh {
		t.Errorf("central rule: %+v", got)
	}
	if len(central.PriorityRules) != 1 {
		t.Fatalf("central top-level rules: %+v", central.PriorityRules)
	}
	if got := central.PriorityRules[0]; got.Protocol != "tcp" || got.Port != "22" || got.Priority != PriorityMax {
		t.Errorf("central top-level rule: %+v", got)
	}
}

// unmarshalT wraps the repo's yaml flavour so the test fails on the first
// parse error instead of drowning in them.
func unmarshalT(t *testing.T, src string, out any) error {
	t.Helper()
	return yaml.Unmarshal([]byte(strings.TrimSpace(src)), out)
}

func TestValidatePriorityRules(t *testing.T) {
	cases := []struct {
		name    string
		rules   []PriorityRule
		wantErr string // "" = valid
	}{
		{"udp single port", []PriorityRule{{Protocol: "udp", Port: "5405", Priority: PriorityHigh}}, ""},
		{"tcp range port", []PriorityRule{{Protocol: "tcp", Port: "5000-5100", Priority: PriorityMedium}}, ""},
		{"icmp no port", []PriorityRule{{Protocol: "icmp", Priority: PriorityMax}}, ""},
		{"dscp override", []PriorityRule{{Protocol: "udp", Port: "5405", Priority: PriorityHigh, Dscp: dscpPtr(10)}}, ""},
		{"dscp zero", []PriorityRule{{Protocol: "udp", Port: "5405", Priority: PriorityHigh, Dscp: dscpPtr(0)}}, ""},
		{"unknown protocol", []PriorityRule{{Protocol: "sctp", Port: "5405", Priority: PriorityHigh}}, `unknown protocol "sctp"`},
		{"tcp without port", []PriorityRule{{Protocol: "tcp", Priority: PriorityHigh}}, "protocol tcp requires a port"},
		{"udp without port", []PriorityRule{{Protocol: "udp", Priority: PriorityHigh}}, "protocol udp requires a port"},
		{"icmp with port", []PriorityRule{{Protocol: "icmp", Port: "5405", Priority: PriorityHigh}}, "icmp rules must not set a port"},
		{"bad port", []PriorityRule{{Protocol: "udp", Port: "notaport", Priority: PriorityHigh}}, "invalid port range"},
		{"inverted range", []PriorityRule{{Protocol: "udp", Port: "6000-5000", Priority: PriorityHigh}}, "invalid port range"},
		{"port zero", []PriorityRule{{Protocol: "udp", Port: "0", Priority: PriorityHigh}}, "port must be greater than 0"},
		{"priority normal", []PriorityRule{{Protocol: "udp", Port: "5405", Priority: "normal"}}, "would change nothing"},
		{"priority empty", []PriorityRule{{Protocol: "udp", Port: "5405", Priority: ""}}, "would change nothing"},
		{"priority unknown", []PriorityRule{{Protocol: "udp", Port: "5405", Priority: "urgent"}}, "unknown priority"},
		{"dscp negative", []PriorityRule{{Protocol: "udp", Port: "5405", Priority: PriorityHigh, Dscp: dscpPtr(-1)}}, "dscp must be a 6-bit codepoint"},
		{"dscp over 63", []PriorityRule{{Protocol: "udp", Port: "5405", Priority: PriorityHigh, Dscp: dscpPtr(64)}}, "dscp must be a 6-bit codepoint"},
		{"exact duplicate", []PriorityRule{
			{Protocol: "udp", Port: "5405", Priority: PriorityHigh},
			{Protocol: "udp", Port: "5405", Priority: PriorityMedium},
		}, "duplicate rule"},
		{"overlapping ok", []PriorityRule{
			{Protocol: "udp", Port: "5400-5500", Priority: PriorityMedium},
			{Protocol: "udp", Port: "5405", Priority: PriorityHigh},
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePriorityRules(tc.rules, "test")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("valid rules rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}

	tooMany := make([]PriorityRule, MaxPriorityRules+1)
	for i := range tooMany {
		tooMany[i] = PriorityRule{Protocol: "udp", Port: PortSpec(itoa(1024 + i)), Priority: PriorityHigh}
	}
	if err := ValidatePriorityRules(tooMany, "test"); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("rule-count cap not enforced: %v", err)
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func TestResolvePriorityRulesPrecedence(t *testing.T) {
	nodeRules := []PriorityRule{{Protocol: "udp", Port: "7999", Priority: PriorityMedium}}
	centralRules := []PriorityRule{{Protocol: "udp", Port: "5405", Priority: PriorityHigh}}
	globalRules := []PriorityRule{{Protocol: "tcp", Port: "22", Priority: PriorityMax}}

	// the node's own routers[] entry wins wholesale
	rules, source, err := ResolvePriorityRules(&RouterCfg{NodeCfg: NodeCfg{Id: "n1"}, PriorityRules: centralRules}, globalRules, &LocalCfg{PriorityRules: nodeRules})
	if err != nil {
		t.Fatal(err)
	}
	if source != "central" || len(rules) != 1 || rules[0].Ports.First != 5405 {
		t.Fatalf("router entry precedence: source=%s rules=%+v", source, rules)
	}

	// the central top-level (mesh-wide) list beats node.yaml
	rules, source, err = ResolvePriorityRules(&RouterCfg{NodeCfg: NodeCfg{Id: "n1"}}, globalRules, &LocalCfg{PriorityRules: nodeRules})
	if err != nil {
		t.Fatal(err)
	}
	if source != "central-global" || len(rules) != 1 || rules[0].Ports.First != 22 {
		t.Fatalf("central-global precedence: source=%s rules=%+v", source, rules)
	}

	// an EMPTY routers[] entry is indistinguishable from an absent one: the
	// mesh-wide list applies (yaml omitempty roundtrips drop empty lists)
	rules, source, err = ResolvePriorityRules(&RouterCfg{NodeCfg: NodeCfg{Id: "n1"}, PriorityRules: []PriorityRule{}}, globalRules, &LocalCfg{PriorityRules: nodeRules})
	if err != nil {
		t.Fatal(err)
	}
	if source != "central-global" || len(rules) != 1 || rules[0].Ports.First != 22 {
		t.Fatalf("empty entry falls to central-global: source=%s rules=%+v", source, rules)
	}

	// an EMPTY top-level list is indistinguishable from an absent one: the
	// node rules apply
	rules, source, err = ResolvePriorityRules(&RouterCfg{NodeCfg: NodeCfg{Id: "n1"}, PriorityRules: []PriorityRule{}}, []PriorityRule{}, &LocalCfg{PriorityRules: nodeRules})
	if err != nil {
		t.Fatal(err)
	}
	if source != "node" || len(rules) != 1 || rules[0].Ports.First != 7999 {
		t.Fatalf("empty central-global falls back: source=%s rules=%+v", source, rules)
	}

	// node rules apply when central sets none anywhere
	rules, source, err = ResolvePriorityRules(&RouterCfg{NodeCfg: NodeCfg{Id: "n1"}}, nil, &LocalCfg{PriorityRules: nodeRules})
	if err != nil {
		t.Fatal(err)
	}
	if source != "node" || len(rules) != 1 || rules[0].Ports.First != 7999 {
		t.Fatalf("node fallback: source=%s rules=%+v", source, rules)
	}

	// default: nothing configured
	rules, source, err = ResolvePriorityRules(&RouterCfg{NodeCfg: NodeCfg{Id: "n1"}}, nil, &LocalCfg{})
	if err != nil {
		t.Fatal(err)
	}
	if source != "default" || rules != nil {
		t.Fatalf("default: source=%s rules=%+v", source, rules)
	}

	// nil central (not a router in central) with mesh-wide rules
	rules, source, err = ResolvePriorityRules(nil, globalRules, &LocalCfg{PriorityRules: nodeRules})
	if err != nil || source != "central-global" || len(rules) != 1 || rules[0].Ports.First != 22 {
		t.Fatalf("nil central with global: source=%s rules=%+v err=%v", source, rules, err)
	}

	// nil central with node rules
	rules, source, err = ResolvePriorityRules(nil, nil, &LocalCfg{PriorityRules: nodeRules})
	if err != nil || source != "node" || len(rules) != 1 {
		t.Fatalf("nil central: source=%s rules=%+v err=%v", source, rules, err)
	}
}

func TestResolvePriorityRulesCompilation(t *testing.T) {
	rules, _, err := ResolvePriorityRules(nil, nil, &LocalCfg{PriorityRules: []PriorityRule{
		{Protocol: "udp", Port: "5405", Priority: PriorityHigh},
		{Protocol: "tcp", Port: "5000-5100", Priority: PriorityMedium, Dscp: dscpPtr(10)},
		{Protocol: "icmp", Priority: PriorityMax},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("got %d rules", len(rules))
	}
	// udp/5405 high: EF on the wire (DSCP 46 << 2)
	if rules[0].Proto != 17 || rules[0].Prio != device.TcHighPriority || rules[0].TOS != 0xb8 {
		t.Errorf("udp rule: %+v", rules[0])
	}
	// tcp/5000-5100 medium with dscp 10: range + AF41-level prio + 10<<2
	if rules[1].Proto != 6 || rules[1].Ports.First != 5000 || rules[1].Ports.Last != 5100 ||
		rules[1].Prio != device.TcMediumPriority || rules[1].TOS != 10<<2 {
		t.Errorf("tcp range rule: %+v", rules[1])
	}
	// icmp max: matches all icmp (invalid range), CS7 on the wire
	if rules[2].Proto != 1 || rules[2].Ports.Valid() || rules[2].Prio != device.TcMaxPriority || rules[2].TOS != 56<<2 {
		t.Errorf("icmp rule: %+v", rules[2])
	}
	// medium default DSCP is AF41
	rules, _, err = ResolvePriorityRules(nil, nil, &LocalCfg{PriorityRules: []PriorityRule{
		{Protocol: "udp", Port: "1", Priority: PriorityMedium},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].TOS != 34<<2 {
		t.Errorf("medium default DSCP: %#02x, want AF41 (34<<2)", rules[0].TOS)
	}
}

func TestResolvePriorityRulesRejectsInvalid(t *testing.T) {
	if _, _, err := ResolvePriorityRules(nil, nil, &LocalCfg{PriorityRules: []PriorityRule{
		{Protocol: "udp", Priority: PriorityHigh}, // no port
	}}); err == nil {
		t.Fatal("invalid rule list accepted by ResolvePriorityRules")
	}
}
