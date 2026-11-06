package state

import (
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
)

// dptr is a small helper for the pointer-typed junk knobs.

// defaultsCentral is the shared fixture: the obf block carries defaults for
// every defaultable parameter; strategy `own` overrides a subset, strategy
// `bare` overrides nothing, strategy `plain` has no defaults to inherit
// where none apply.
const defaultsCentral = `
obf:
  s1: 32
  ports: "40000-50000"
  port_hopping_mode: timed
  port_hopping:
    period_seconds: 30
  jc: 5
  jmin: 250
  jmax: 800
  i1: "deadbeef"
  i2: "cafebabe"
  strategy_mode: fixed
  strategy:
    own:
      ports: "51820"
      port_hopping_mode: reactive
      jc: 7
      jmin: 300
      i1: "11111111"
    bare: {}
    plain:
      ports: "60000"
      jc: 7
      jmin: 300
      jmax: 800
`

func parseDefaultsCentral(t *testing.T) *CentralCfg {
	t.Helper()
	var cfg CentralCfg
	if err := yaml.UnmarshalWithOptions([]byte(defaultsCentral), &cfg, yaml.Strict()); err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	return &cfg
}

// TestObfDefaultsResolution pins the per-field inheritance: every unset
// strategy parameter inherits the obf-level default, every set parameter
// wins. The RAW map must stay untouched (the operator's shape is what the
// seal and the local cache serialize).
func TestObfDefaultsResolution(t *testing.T) {
	cfg := parseDefaultsCentral(t)
	m := cfg.ObfStrategies()

	own := m["own"]
	if own.Ports != "51820" {
		t.Errorf("own.Ports: strategy value must win, got %q", own.Ports)
	}
	if own.PortHoppingMode != "reactive" {
		t.Errorf("own.PortHoppingMode: strategy value must win, got %q", own.PortHoppingMode)
	}
	if own.Jc == nil || *own.Jc != 7 || own.Jmin == nil || *own.Jmin != 300 {
		t.Errorf("own junk: strategy values must win, got %+v", own.Jc)
	}
	if own.Jmax == nil || *own.Jmax != 800 {
		t.Errorf("own.Jmax must inherit the default (unset in the strategy), got %v", own.Jmax)
	}
	if own.I1 != "11111111" {
		t.Errorf("own.I1: strategy value must win, got %q", own.I1)
	}
	if own.I2 != "cafebabe" {
		t.Errorf("own.I2 must inherit the default slot, got %q", own.I2)
	}
	if own.PortHopping == nil || own.PortHopping.PeriodSeconds == nil || *own.PortHopping.PeriodSeconds != 30 {
		t.Errorf("own.PortHopping must inherit the default block, got %+v", own.PortHopping)
	}

	bare := m["bare"]
	if bare.Ports != "40000-50000" {
		t.Errorf("bare.Ports must inherit, got %q", bare.Ports)
	}
	if bare.PortHoppingMode != "timed" {
		t.Errorf("bare.PortHoppingMode must inherit, got %q", bare.PortHoppingMode)
	}
	if bare.Jc == nil || *bare.Jc != 5 || bare.Jmin == nil || *bare.Jmin != 250 || bare.Jmax == nil || *bare.Jmax != 800 {
		t.Errorf("bare junk must inherit, got %+v", bare)
	}
	if bare.I1 != "deadbeef" || bare.I5 != "" {
		t.Errorf("bare i-set must inherit per slot, got %q..%q", bare.I1, bare.I5)
	}

	// the RAW operator shape is untouched
	raw := cfg.Obf.Strategy
	if raw["bare"].Ports != "" || raw["bare"].Jc != nil || raw["bare"].PortHoppingMode != "" {
		t.Errorf("the raw strategy map was materialized — the operator's shape must serialize unchanged: %+v", raw["bare"])
	}
	if cfg.Obf.Ports != "40000-50000" || cfg.Obf.Jc == nil || *cfg.Obf.Jc != 5 {
		t.Errorf("the obf defaults must stay on the block: ports=%q jc=%v", cfg.Obf.Ports, cfg.Obf.Jc)
	}
}

// TestObfDefaultsNoDefaultsFastPath pins back-compat: with no defaults
// configured, ObfStrategies() serves the strategies exactly as written
// (nothing to inherit anywhere).
func TestObfDefaultsNoDefaultsFastPath(t *testing.T) {
	central := `
obf:
  strategy:
    a:
      ports: "40000"
  strategy_mode: fixed
`
	var cfg CentralCfg
	if err := yaml.UnmarshalWithOptions([]byte(central), &cfg, yaml.Strict()); err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	m := cfg.ObfStrategies()
	if m["a"].Ports != "40000" {
		t.Errorf("no-defaults resolution changed the strategy: %+v", m["a"])
	}
}

// TestObfDefaultsEffectiveConsumers pins that the value consumers see the
// resolved strategies: the listen union derives from inherited ports, and
// the device junk resolution treats inherited values as the strategy's own.
func TestObfDefaultsEffectiveConsumers(t *testing.T) {
	cfg := parseDefaultsCentral(t)
	m := cfg.ObfStrategies()

	// bare inherits the default range: the union of own (51820) + bare
	// (40000-50000) + plain (60000) must merge into 40000-50000,51820,60000.
	// An untagged endpoint means "every strategy", so all three contribute.
	router := &RouterCfg{Endpoints: []string{"hub.example.com"}}
	prs, err := ListenUnionRanges(router, m)
	if err != nil {
		t.Fatalf("ListenUnionRanges: %v", err)
	}
	if got := RangesString(prs); got != "40000-50000,51820,60000" {
		t.Errorf("listen union over resolved strategies: got %s", got)
	}

	// hop policy: own overrides to reactive; bare inherits timed+period
	p := ResolveStrategyHopPolicy(m["bare"])
	if p.Mode != HopModeTimed || p.Period != 30*time.Second {
		t.Errorf("bare resolved policy: %+v", p)
	}
	p = ResolveStrategyHopPolicy(m["own"])
	if p.Mode != HopModeReactive {
		t.Errorf("own resolved policy: %+v", p)
	}

	// junk: bare and own must AGREE through the defaults (bare inherits
	// jmax=800 like own; bare inherits jc=5 but own sets jc=7 — they
	// disagree on jc, so the coherence check must fire over the resolved
	// values)
	_, _, err = EffectiveStrategyJunk(m, []string{"bare", "own"})
	if err == nil || !strings.Contains(err.Error(), "different jc") {
		t.Errorf("junk coherence must run over the resolved values, got: %v", err)
	}
	// two strategies that BOTH inherit the full default trio agree through
	// the defaults and resolve to one junk configuration
	junk, src, err := EffectiveStrategyJunk(m, []string{"bare"})
	if err != nil {
		t.Fatalf("junk over bare (inherited): %v", err)
	}
	if junk.Jc != 5 || junk.Jmin != 250 || junk.Jmax != 800 || junk.I[0] != "deadbeef" || src != "bare" {
		t.Errorf("resolved junk: %+v from %q", junk, src)
	}
}

// TestObfDefaultsValidation pins the defaults-block validation: a bogus
// default fails loudly even when every defined strategy overrides the
// parameter (dead config is dead config, wherever it sits).
func TestObfDefaultsValidation(t *testing.T) {
	base := func(defaults string) string {
		return `
obf:
` + defaults + `
  strategy:
    a:
      ports: "40000"
  strategy_mode: fixed
`
	}
	cases := []struct {
		name    string
		in      string
		wantErr string
	}{
		{"bad ports", base("  ports: \"not-a-range\"\n"), "obf: default ports"},
		{"jmin without jc", base("  jmin: 250\n"), "obf defaults: jmin/jmax are set but jc is not positive"},
		{"jc without jmin", base("  jc: 5\n"), "obf defaults: jc requires the jmin/jmax"},
		{"jmin over jmax", base("  jc: 5\n  jmin: 800\n  jmax: 250\n"), "obf defaults: jmin (800) must not exceed jmax (250)"},
		{"bogus hop mode", base("  port_hopping_mode: dynamic\n"), "obf defaults"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg CentralCfg
			if err := yaml.UnmarshalWithOptions([]byte(tc.in), &cfg, yaml.Strict()); err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			err := CentralConfigValidator(&cfg)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("want error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

// TestObfDefaultsCompleteMissingPorts pins the original reason the defaults
// exist: a strategy may omit `ports` entirely when the obf level carries a
// default — validation passes and the effective map carries the range.
func TestObfDefaultsCompleteMissingPorts(t *testing.T) {
	central := `
obf:
  ports: "40000-50000"
  strategy:
    a: {}
  strategy_mode: fixed
`
	var cfg CentralCfg
	if err := yaml.UnmarshalWithOptions([]byte(central), &cfg, yaml.Strict()); err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	if err := CentralConfigValidator(&cfg); err != nil {
		t.Fatalf("validation with inherited ports: %v", err)
	}
	if m := cfg.ObfStrategies(); m["a"].Ports != "40000-50000" {
		t.Errorf("effective ports: %+v", m["a"])
	}

	// and without a default the same config must still fail loudly
	var cfg2 CentralCfg
	noDefault := strings.Replace(central, "  ports: \"40000-50000\"\n", "", 1)
	if err := yaml.UnmarshalWithOptions([]byte(noDefault), &cfg2, yaml.Strict()); err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	if err := CentralConfigValidator(&cfg2); err == nil || !strings.Contains(err.Error(), "ports is required") {
		t.Errorf("missing ports without defaults must fail, got: %v", err)
	}
}

// TestObfDefaultsMarshalKeepsRawShape pins serialization: the defaults stay
// at the obf level and the strategies stay as written — through a plain
// marshal and through the seal roundtrip — so the operator's shape is what
// the bundle and the local cache carry.
func TestObfDefaultsMarshalKeepsRawShape(t *testing.T) {
	cfg := parseDefaultsCentral(t)
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "ports: 40000-50000") {
		t.Errorf("the obf defaults must marshal at the obf level:\n%s", s)
	}
	if !strings.Contains(s, "    own:\n      ports: \"51820\"") {
		t.Errorf("the own strategy must keep its explicit shape:\n%s", s)
	}
	// the roundtrip re-resolves identically
	var rt CentralCfg
	if err := yaml.UnmarshalWithOptions(out, &rt, yaml.Strict()); err != nil {
		t.Fatalf("roundtrip strict decode: %v\n%s", err, s)
	}
	if m := rt.ObfStrategies(); m["bare"].Ports != "40000-50000" || m["own"].Jmax == nil || *m["own"].Jmax != 800 {
		t.Errorf("roundtrip lost the defaults resolution: %+v %+v", m["bare"], m["own"])
	}

	// the seal keeps the raw shape in the distributed bundle
	key := GenerateKey()
	bundle, err := BundleConfig(defaultsCentral, key)
	if err != nil {
		t.Fatalf("BundleConfig: %v", err)
	}
	text, uncfg, err := UnbundleConfigText(bundle, key.Pubkey())
	if err != nil {
		t.Fatalf("UnbundleConfigText: %v", err)
	}
	if !strings.Contains(text, "ports: 40000-50000") {
		t.Errorf("the bundle must carry the defaults at the obf level (raw shape):\n%s", text)
	}
	if m := uncfg.ObfStrategies(); m["bare"].Ports != "40000-50000" {
		t.Errorf("unbundled resolution lost the defaults: %+v", m["bare"])
	}
}

// TestObfDefaultsJunkTrioCompletion pins per-field inheritance producing a
// complete trio: a strategy that sets only `jc` completes its size range
// from the defaults and is internally valid.
func TestObfDefaultsJunkTrioCompletion(t *testing.T) {
	central := `
obf:
  jc: 5
  jmin: 250
  jmax: 800
  strategy:
    a:
      ports: "40000"
      jc: 9
  strategy_mode: fixed
`
	var cfg CentralCfg
	if err := yaml.UnmarshalWithOptions([]byte(central), &cfg, yaml.Strict()); err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	if err := CentralConfigValidator(&cfg); err != nil {
		t.Fatalf("validation with an inherited size range: %v", err)
	}
	m := cfg.ObfStrategies()
	if m["a"].Jc == nil || *m["a"].Jc != 9 || m["a"].Jmin == nil || *m["a"].Jmin != 250 {
		t.Errorf("trio completion: %+v", m["a"])
	}
}
