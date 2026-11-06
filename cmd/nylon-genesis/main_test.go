package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	amnezigo "github.com/Arsolitt/amnezigo"
	"github.com/encodeous/nylon/state"
	"github.com/goccy/go-yaml"
)

// generate runs the generator into a temp file and unmarshals the output
// into state.CentralCfg, proving the fragment is paste-ready.
//
// Generation is driven by package-global crypto/rand, so the checks below
// are structural only: exact output bytes are never asserted.
func generate(t *testing.T, presetName string, random bool, protocol string, mtu int, strategyName string, strategyPorts string, compat bool) state.CentralCfg {
	t.Helper()
	outPath := filepath.Join(t.TempDir(), "out.yaml")
	if err := run(presetName, random, protocol, mtu, strategyName, strategyPorts, compat, outPath, false); err != nil {
		t.Fatalf("run(preset=%q, random=%v, protocol=%q, mtu=%d, strategy=%q, ports=%q, compat=%v) failed: %v",
			presetName, random, protocol, mtu, strategyName, strategyPorts, compat, err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading generated output: %v", err)
	}
	// Strict pins the fragment to the current schema: a leftover field (the
	// retired `protocol` label, junk on the mesh-wide profile) fails here
	// instead of sailing through as an ignored key.
	var cfg state.CentralCfg
	if err := yaml.UnmarshalWithOptions(data, &cfg, yaml.Strict()); err != nil {
		t.Fatalf("generated output does not unmarshal strictly into state.CentralCfg: %v\noutput:\n%s", err, data)
	}
	return cfg
}

// validateProfile re-runs the amnezigo obfuscation sub-validators over a
// generated (non-compat) fragment: per-H range viability on the mesh-wide
// profile plus the AWG 2.0 size invariant for the strategy's junk — the
// I-packet lengths against the strategy's jmin/jmax range. It also asserts
// the GenerateHeaderRanges invariant: generated ranges stay clear of the
// vanilla WG message type-ids 1..4.
func validateProfile(t *testing.T, profile *state.ObfProfile, strat *state.ObfStrategy) {
	t.Helper()
	if profile == nil {
		t.Fatal("central awg_profile is nil")
	}
	for i, h := range [4]state.ObfHeaderRange{profile.H1, profile.H2, profile.H3, profile.H4} {
		if err := amnezigo.ValidateHeaderRange(amnezigo.HeaderRange{Min: h.Min, Max: h.Max}); err != nil {
			t.Errorf("h%d failed ValidateHeaderRange: %v", i+1, err)
		}
		if h.Min <= 4 {
			t.Errorf("h%d min (%d) must exceed the vanilla WG type-id window 1..4", i+1, h.Min)
		}
	}
	if strat.Jc == nil || strat.Jmin == nil || strat.Jmax == nil {
		t.Fatalf("strategy junk trio missing from the fragment: %+v", strat)
	}
	iSizes := []int{
		amnezigo.CPSLength(strat.I1),
		amnezigo.CPSLength(strat.I2),
		amnezigo.CPSLength(strat.I3),
		amnezigo.CPSLength(strat.I4),
		amnezigo.CPSLength(strat.I5),
	}
	if err := amnezigo.ValidatePacketSizes(
		int(profile.S1), int(profile.S2), int(profile.S3), int(profile.S4),
		iSizes, int(*strat.Jmin), int(*strat.Jmax),
	); err != nil {
		t.Errorf("packet sizes invalid for strategy junk %q: %v", strat.I1, err)
	}
}

// strategyOf fetches the single generated strategy or fails the test.
func strategyOf(t *testing.T, cfg state.CentralCfg) (string, *state.ObfStrategy) {
	t.Helper()
	if len(cfg.ObfStrategies) != 1 {
		t.Fatalf("expected exactly 1 obf strategy, got %d (%v)", len(cfg.ObfStrategies), cfg.ObfStrategies)
	}
	for name, s := range cfg.ObfStrategies {
		return name, s
	}
	return "", nil
}

func TestGeneratePresetStrategyValidates(t *testing.T) {
	cfg := generate(t, "standard-1420", false, "quic", 1420, "", "40000-41000", false)

	if cfg.AwgProfile == nil {
		t.Fatal("awg_profile is nil")
	}
	name, strat := strategyOf(t, cfg)
	if name != "quic" {
		t.Errorf("strategy name = %q, want %q (defaults to the protocol template name)", name, "quic")
	}
	if strat.Ports != "40000-41000" {
		t.Errorf("strategy.Ports = %q, want %q", strat.Ports, "40000-41000")
	}
	// the protocol label is GONE: the strategy name is its identity, and
	// generate() above proves the fragment unmarshals strictly — a leftover
	// `protocol:` key would fail there
	if strat.Jc == nil || *strat.Jc == 0 || strat.Jmin == nil || *strat.Jmin == 0 || strat.Jmax == nil || *strat.Jmax == 0 {
		t.Errorf("strategy junk trio missing or zero: %+v", strat)
	}
	// Named protocol templates fill I1-I4; I5 is intentionally left empty
	// by the amnezigo oracle (see DNSTemplate et al.).
	for j, seq := range []string{strat.I1, strat.I2, strat.I3, strat.I4} {
		if seq == "" {
			t.Errorf("strategy.I%d is empty", j+1)
		}
	}
	validateProfile(t, cfg.AwgProfile, strat)

	// the fragment must validate as part of a full central config with a
	// tagged endpoint using it (two routers so the graph pairing is valid)
	cfg.Routers = []state.RouterCfg{
		{
			NodeCfg:   state.NodeCfg{Id: "hub", PubKey: state.GenerateKey().Pubkey()},
			Endpoints: []string{"hub.example.com[quic]"},
		},
		{
			NodeCfg:   state.NodeCfg{Id: "leaf", PubKey: state.GenerateKey().Pubkey()},
			Endpoints: []string{"leaf.example.com[quic]"},
		},
	}
	cfg.Graph = []string{"hub, leaf"}
	if err := state.CentralConfigValidator(&cfg); err != nil {
		t.Errorf("central config with the generated fragment does not validate: %v", err)
	}
}

func TestGenerateCompatProfile(t *testing.T) {
	cfg := generate(t, defaultPreset, false, "quic", 0, "compat", "51820", true)

	if cfg.AwgProfile == nil {
		t.Fatal("central awg_profile is nil")
	}
	want := [4]state.ObfHeaderRange{
		{Min: 1, Max: 1}, {Min: 2, Max: 2}, {Min: 3, Max: 3}, {Min: 4, Max: 4},
	}
	for i, h := range [4]state.ObfHeaderRange{cfg.AwgProfile.H1, cfg.AwgProfile.H2, cfg.AwgProfile.H3, cfg.AwgProfile.H4} {
		if h != want[i] {
			t.Errorf("h%d = {%d,%d}, want {%d,%d}", i+1, h.Min, h.Max, want[i].Min, want[i].Max)
		}
	}
	for name, v := range map[string]uint32{
		"s1": cfg.AwgProfile.S1, "s2": cfg.AwgProfile.S2, "s3": cfg.AwgProfile.S3, "s4": cfg.AwgProfile.S4,
	} {
		if v != 0 {
			t.Errorf("%s = %d, want 0 in compat profile", name, v)
		}
	}

	_, strat := strategyOf(t, cfg)
	if strat.Ports != "51820" {
		t.Errorf("compat strategy.Ports = %q, want 51820", strat.Ports)
	}
	if strat.Jc != nil || strat.Jmin != nil || strat.Jmax != nil {
		t.Errorf("compat strategy must carry no junk trio: %+v", strat)
	}
	for j, seq := range []string{strat.I1, strat.I2, strat.I3, strat.I4, strat.I5} {
		if seq != "" {
			t.Errorf("compat strategy.I%d must be empty (no junk in the vanilla-compat dialect)", j+1)
		}
	}
}

func TestGenerateRandomStrategyValidates(t *testing.T) {
	cfg := generate(t, "standard-1420", true, "dns", 1420, "", "51820", false)

	_, strat := strategyOf(t, cfg)
	// Named templates leave I5 empty by design (see the amnezigo oracle);
	// I1-I4 must be filled.
	for j, seq := range []string{strat.I1, strat.I2, strat.I3, strat.I4} {
		if seq == "" {
			t.Errorf("strategy.I%d is empty", j+1)
		}
	}
	validateProfile(t, cfg.AwgProfile, strat)
}

// TestGenerateRandomRedrawIsValid drives both shared-profile sources with
// protocol "random": the strategy's I lengths are drawn independently of the
// padded handshake sizes and a colliding draw is redrawn (measured ~11%
// collision per draw at mtu 1420; the 64-attempt budget leaves a residual
// failure probability far below a coin flip).
func TestGenerateRandomRedrawIsValid(t *testing.T) {
	for _, tc := range []struct {
		name         string
		randomShared bool
	}{
		{name: "random shared profile", randomShared: true},
		{name: "preset shared profile", randomShared: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := generate(t, "standard-1420", tc.randomShared, amnezigo.ProtocolRandom, 1420, "obf_main", "30000-31000", false)
			_, strat := strategyOf(t, cfg)
			if strat.Ports != "30000-31000" {
				t.Errorf("strategy.Ports = %q, want 30000-31000", strat.Ports)
			}
			// Random mode fills every interval.
			for j, seq := range []string{strat.I1, strat.I2, strat.I3, strat.I4, strat.I5} {
				if seq == "" {
					t.Errorf("strategy.I%d is empty", j+1)
				}
			}
			validateProfile(t, cfg.AwgProfile, strat)
		})
	}
}

func TestGenerateUnknownProtocolFails(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "out.yaml")
	err := run("standard-1420", false, "smtp", 1420, "", "51820", false, outPath, false)
	if err == nil {
		t.Fatal("expected an error for unknown protocol, got nil")
	}
	if _, statErr := os.Stat(outPath); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("no output file should be created on error; stat err = %v", statErr)
	}
}

func TestGenerateInvalidStrategyNameOrPortsFails(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "out.yaml")
	if err := run("standard-1420", false, "quic", 1420, "Not Valid!", "51820", false, outPath, false); err == nil {
		t.Error("invalid strategy name accepted")
	}
	if err := run("standard-1420", false, "quic", 1420, "", "not-ports", false, outPath, false); err == nil {
		t.Error("invalid strategy ports accepted")
	}
	if _, statErr := os.Stat(outPath); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("no output file should be created on error; stat err = %v", statErr)
	}
}
