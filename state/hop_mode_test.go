package state

import (
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
)

func hopStr(v uint32) *uint32 { return &v }

// TestHopModeParsingRoundtrip pins the YAML surface of the hop policy on both
// the node (node.yaml) and the router (central.yaml) sides.
func TestHopModeParsingRoundtrip(t *testing.T) {
	const nodeYaml = `
id: node1
port: 30000
port_mode: timed
port_hopping:
  period_seconds: 300
  period_jitter_pct: 15
  cooldown_seconds: 60
`
	var node LocalCfg
	if err := yaml.Unmarshal([]byte(nodeYaml), &node); err != nil {
		t.Fatalf("node yaml: %v", err)
	}
	if node.PortMode != HopModeTimed {
		t.Errorf("port_mode = %q, want %q", node.PortMode, HopModeTimed)
	}
	if node.PortHopping == nil || node.PortHopping.PeriodSeconds == nil || *node.PortHopping.PeriodSeconds != 300 {
		t.Fatalf("period_seconds not parsed: %+v", node.PortHopping)
	}
	if node.PortHopping.PeriodJitterPct == nil || *node.PortHopping.PeriodJitterPct != 15 {
		t.Fatalf("period_jitter_pct not parsed: %+v", node.PortHopping)
	}

	const centralYaml = `
routers:
- id: node2
  port_mode: proactive
  port_hopping:
    budget_packets: 24
  endpoints: []
`
	var central CentralCfg
	if err := yaml.Unmarshal([]byte(centralYaml), &central); err != nil {
		t.Fatalf("central yaml: %v", err)
	}
	if len(central.Routers) != 1 {
		t.Fatalf("routers = %d, want 1", len(central.Routers))
	}
	r := central.Routers[0]
	if r.PortMode != HopModeProactive {
		t.Errorf("router port_mode = %q, want %q", r.PortMode, HopModeProactive)
	}
	if r.PortHopping == nil || r.PortHopping.BudgetPackets == nil || *r.PortHopping.BudgetPackets != 24 {
		t.Fatalf("budget_packets not parsed: %+v", r.PortHopping)
	}

	// the router hop fields must survive a marshal/unmarshal roundtrip
	out, err := yaml.Marshal(&central)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var central2 CentralCfg
	if err := yaml.Unmarshal(out, &central2); err != nil {
		t.Fatalf("re-unmarshal: %v (yaml: %s)", err, out)
	}
	if central2.Routers[0].PortMode != HopModeProactive || central2.Routers[0].PortHopping.BudgetPackets == nil {
		t.Errorf("hop policy lost in roundtrip: %+v", central2.Routers[0])
	}
}

// TestValidateHopPolicyCfgMatrix walks the full validation matrix of one
// file's hop policy.
func TestValidateHopPolicyCfgMatrix(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		cfg     *PortHoppingCfg
		wantErr string // "" = expect success
	}{
		{"no policy at all", "", nil, ""},
		{"static without block", HopModeStatic, nil, ""},
		{"static with ignored budget", HopModeStatic, &PortHoppingCfg{BudgetPackets: hopStr(12)}, ""},
		{"reactive without block", HopModeReactive, nil, ""},
		{"reactive with ignored budget", HopModeReactive, &PortHoppingCfg{BudgetPackets: hopStr(12)}, ""},
		{"proactive without block", HopModeProactive, nil, "requires port_hopping.budget_packets"},
		{"proactive without budget", HopModeProactive, &PortHoppingCfg{CooldownSeconds: hopStr(5)}, "requires port_hopping.budget_packets"},
		{"proactive with budget", HopModeProactive, &PortHoppingCfg{BudgetPackets: hopStr(12)}, ""},
		{"timed without block", HopModeTimed, nil, "requires port_hopping.period_seconds"},
		{"timed without period", HopModeTimed, &PortHoppingCfg{BudgetPackets: hopStr(12)}, "requires port_hopping.period_seconds"},
		{"timed with period", HopModeTimed, &PortHoppingCfg{PeriodSeconds: hopStr(300)}, ""},
		{"timed with period and jitter", HopModeTimed, &PortHoppingCfg{PeriodSeconds: hopStr(300), PeriodJitterPct: hopStr(25)}, ""},
		{"timed with zero period", HopModeTimed, &PortHoppingCfg{PeriodSeconds: hopStr(0)}, "period_seconds must be greater than 0"},
		{"timed with excess jitter", HopModeTimed, &PortHoppingCfg{PeriodSeconds: hopStr(300), PeriodJitterPct: hopStr(51)}, "period_jitter_pct must be at most 50"},
		{"knobs without mode (migration guard)", "", &PortHoppingCfg{BudgetPackets: hopStr(12)}, "port_mode is not set"},
		{"unknown mode", "surprise", nil, "unknown port_mode"},
		{"reserved dynamic", HopModeDynamic, nil, "reserved for a future release"},
		{"reserved auto", HopModeAuto, nil, "reserved for a future release"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHopPolicyCfg(tc.mode, tc.cfg, "test config")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestHopPolicyNodeValidation wires the hop rules into the node config
// validator.
func TestHopPolicyNodeValidation(t *testing.T) {
	base := func() *LocalCfg {
		return &LocalCfg{Id: "node1", Port: 30000, Key: [32]byte{1}}
	}

	node := base()
	node.PortHopping = &PortHoppingCfg{BudgetPackets: hopStr(12)}
	if err := NodeConfigValidator(nil, node); err == nil || !strings.Contains(err.Error(), "port_mode is not set") {
		t.Errorf("node port_hopping without port_mode: err = %v, want migration guard", err)
	}

	node = base()
	node.PortMode = HopModeProactive
	if err := NodeConfigValidator(nil, node); err == nil || !strings.Contains(err.Error(), "budget_packets") {
		t.Errorf("node proactive without budget: err = %v, want requirement error", err)
	}

	node = base()
	node.PortMode = HopModeTimed
	node.PortHopping = &PortHoppingCfg{PeriodSeconds: hopStr(60)}
	if err := NodeConfigValidator(nil, node); err != nil {
		t.Errorf("node timed with period: unexpected error %v", err)
	}

	node = base()
	node.PortMode = HopModeAuto
	if err := NodeConfigValidator(nil, node); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("node reserved mode: err = %v, want reserved error", err)
	}
}

// TestHopPolicyCentralValidation wires the hop rules into the central config
// validator (per-router).
func TestHopPolicyCentralValidation(t *testing.T) {
	mk := func(mode string, hop *PortHoppingCfg) *CentralCfg {
		return &CentralCfg{
			Routers: []RouterCfg{{
				NodeCfg:     NodeCfg{Id: "node1"},
				PortMode:    mode,
				PortHopping: hop,
			}},
		}
	}

	if err := CentralConfigValidator(mk(HopModeProactive, nil)); err == nil || !strings.Contains(err.Error(), "router node1") {
		t.Errorf("central proactive without budget: err = %v, want router-scoped requirement error", err)
	}
	if err := CentralConfigValidator(mk(HopModeTimed, &PortHoppingCfg{PeriodSeconds: hopStr(90)})); err != nil {
		t.Errorf("central timed with period: unexpected error %v", err)
	}
	if err := CentralConfigValidator(mk("", &PortHoppingCfg{BudgetPackets: hopStr(12)})); err == nil || !strings.Contains(err.Error(), "port_mode is not set") {
		t.Errorf("central knobs without mode: err = %v, want migration guard", err)
	}
}

// TestResolveHopPolicyPrecedence pins the atomic central > node > default
// precedence of the effective hop policy.
func TestResolveHopPolicyPrecedence(t *testing.T) {
	local := &LocalCfg{
		PortMode: HopModeTimed,
		PortHopping: &PortHoppingCfg{
			PeriodSeconds:   hopStr(60),
			PeriodJitterPct: hopStr(20),
		},
	}

	// central pair wins wholesale; node.yaml hop fields are ignored
	central := &RouterCfg{
		PortMode: HopModeProactive,
		PortHopping: &PortHoppingCfg{
			BudgetPackets: hopStr(40),
		},
	}
	p, src := ResolveHopPolicy(central, local)
	if src != "central" {
		t.Fatalf("source = %q, want central", src)
	}
	if p.Mode != HopModeProactive || p.Budget != 40 {
		t.Errorf("central policy not applied wholesale: %+v", p)
	}
	if p.Period != 0 {
		t.Errorf("node period leaked into the central policy: %+v", p)
	}

	// no central hop fields: the node pair applies
	p, src = ResolveHopPolicy(&RouterCfg{NodeCfg: NodeCfg{Id: "node1"}}, local)
	if src != "node" {
		t.Fatalf("source = %q, want node", src)
	}
	if p.Mode != HopModeTimed || p.Period != 60*time.Second || p.JitterPct != 20 {
		t.Errorf("node policy not applied: %+v", p)
	}

	// nothing anywhere: the static default
	p, src = ResolveHopPolicy(nil, &LocalCfg{})
	if src != "default" || p.Mode != HopModeStatic {
		t.Errorf("default policy: %+v source=%q", p, src)
	}
	if p.Budget != 12 || p.JitterPct != 10 {
		t.Errorf("default knobs drifted: %+v", p)
	}

	// knobs resolution: unset jitter keeps the default, explicit period wins
	p, _ = ResolveHopPolicy(nil, &LocalCfg{PortMode: HopModeTimed, PortHopping: &PortHoppingCfg{PeriodSeconds: hopStr(5)}})
	if p.Period != 5*time.Second || p.JitterPct != 10 {
		t.Errorf("timed knob resolution: %+v", p)
	}
}

// TestValidateHopMode covers the mode-name classifier directly.
func TestValidateHopMode(t *testing.T) {
	for _, m := range HopModes() {
		if err := ValidateHopMode(m); err != nil {
			t.Errorf("implemented mode %q rejected: %v", m, err)
		}
	}
	for _, m := range ReservedHopModes() {
		err := ValidateHopMode(m)
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("reserved mode %q: err = %v, want reserved error", m, err)
		}
	}
	if err := ValidateHopMode("fast"); err == nil || !strings.Contains(err.Error(), "unknown port_mode") {
		t.Errorf("unknown mode: err = %v, want unknown error", err)
	}
}
