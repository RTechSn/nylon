package state

import (
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
)

// TestBundleConfigPreservesComments pins the seal comment contract: a
// hand-written central.yaml carries comments in every position (top-of-file,
// head, trailing, standalone between list items, inside the global obf block
// down to individual strategy entries), and `nylon seal` must keep them in
// the sealed plaintext so `nylon open` (UnbundleConfigText) shows the bundle
// exactly as the operator documented it. Before the fix, seal re-marshalled
// the config from the parsed struct and ate every comment.
func TestBundleConfigPreservesComments(t *testing.T) {
	key := GenerateKey()
	pub := key.Pubkey()
	pubText := func(k NyPublicKey) string {
		b, err := k.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText: %v", err)
		}
		return string(b)
	}

	central := `# top-of-file comment
# the whole-mesh definition
dist:
  key: ` + pubText(pub) + ` # trailing on the dist key
  # head comment inside dist
  repos:
    - file:central.nybundle # trailing on a list item
    # standalone between list items
    - https://static.example.com/network1.nybundle
# standalone between top-level keys
obf:
  s1: 32 # the mesh-wide S/H dialect, inline
  s2: 28
  s3: 20
  s4: 16
  h1: # header ranges must not overlap
    min: 100
    max: 5000000
  # the named strategy map
  strategy:
    awg_main: # the strategy name is its identity
      ports: "40000" # required: one port or a range
      jc: 5
      jmin: 250
      jmax: 800
routers:
  - id: hub # trailing on a map inside a list
    pubkey: ` + pubText(key.Pubkey()) + `
    endpoints:
      - hub.example.com[awg_main]
      # standalone before the last list item
      - hub-lan.example.com[awg_main]
  - id: leaf
    pubkey: ` + pubText(GenerateKey().Pubkey()) + `
graph:
  - hub, leaf # the peering graph
timestamp: 1740832962209309000 # updated by the seal
`

	bundle, err := BundleConfig(central, key)
	if err != nil {
		t.Fatalf("BundleConfig: %v", err)
	}

	text, cfg, err := UnbundleConfigText(bundle, pub)
	if err != nil {
		t.Fatalf("UnbundleConfigText: %v", err)
	}

	// every comment position must survive into the sealed plaintext
	want := []string{
		"# top-of-file comment",
		"# the whole-mesh definition",
		"# trailing on the dist key",
		"# head comment inside dist",
		"# trailing on a list item",
		"# standalone between list items",
		"# standalone between top-level keys",
		"# the mesh-wide S/H dialect, inline",
		"# header ranges must not overlap",
		"# the named strategy map",
		"# the strategy name is its identity",
		"# required: one port or a range",
		"# trailing on a map inside a list",
		"# standalone before the last list item",
		"# the peering graph",
		"# updated by the seal",
	}
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Errorf("comment %q was eaten by the seal; sealed plaintext:\n%s", w, text)
		}
	}

	// the sealed plaintext is live config: it re-parses strictly, keeps the
	// values, and the seal stamped a fresh timestamp
	if cfg.Timestamp == 1740832962209309000 {
		t.Errorf("seal did not stamp a fresh timestamp: %d", cfg.Timestamp)
	}
	if age := time.Since(time.Unix(0, cfg.Timestamp)); age < -time.Minute || age > time.Minute {
		t.Errorf("stamped timestamp is not fresh: %s", age)
	}
	if profile := cfg.Profile(); profile == nil || profile.S1 != 32 || profile.H1.Max != 5000000 {
		t.Errorf("obf profile lost through the seal: %+v", profile)
	}
	strat := cfg.ObfStrategies()["awg_main"]
	if strat == nil || strat.Ports != "40000" || strat.Jc == nil || *strat.Jc != 5 {
		t.Errorf("obf strategy lost through the seal: %+v", strat)
	}

	// and the bundle text itself unmarshals strictly with the values intact
	var round CentralCfg
	if err := yaml.UnmarshalWithOptions([]byte(text), &round, yaml.Strict()); err != nil {
		t.Fatalf("sealed plaintext does not re-parse strictly: %v\ntext:\n%s", err, text)
	}
	if len(round.Routers) != 2 || round.Routers[0].Id != "hub" || len(round.Routers[0].Endpoints) != 2 {
		t.Errorf("routers lost through the seal: %+v", round.Routers)
	}
}

// TestBundleConfigCommentFreeConfigUnchanged pins that a config without
// comments seals exactly as before (no stray comment artefacts) and the
// bundle still round-trips.
func TestBundleConfigCommentFreeConfigUnchanged(t *testing.T) {
	key := GenerateKey()
	pub := key.Pubkey()
	pubText := func(k NyPublicKey) string {
		b, err := k.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText: %v", err)
		}
		return string(b)
	}
	central := `dist:
  key: ` + pubText(pub) + `
routers:
  - id: a
    pubkey: ` + pubText(key.Pubkey()) + `
`
	bundle, err := BundleConfig(central, key)
	if err != nil {
		t.Fatalf("BundleConfig: %v", err)
	}
	text, cfg, err := UnbundleConfigText(bundle, pub)
	if err != nil {
		t.Fatalf("UnbundleConfigText: %v", err)
	}
	if strings.Contains(text, "#") {
		t.Errorf("comment-free config gained comment artefacts:\n%s", text)
	}
	if len(cfg.Routers) != 1 || cfg.Routers[0].Id != "a" {
		t.Errorf("round-trip lost the router: %+v", cfg.Routers)
	}
}
