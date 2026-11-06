package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
)

// The comment lifecycle contract (config reform, round 2):
//
//   - the operator's raw central.yaml is the ONLY place comments live;
//     nothing may strip them from that file — in particular the running
//     daemon, which refreshes the local central.yaml cache on every applied
//     config update (`file:` repos on the admin node made this visible:
//     the poll applied the freshly sealed bundle and wrote a comment-free
//     re-marshal over the hand-written file);
//   - the seal (central.nybundle generation) STRIPS comments — the
//     distributed bundle is clean config;
//   - the daemon's cache refresh (MarshalPreservingComments) keeps the
//     comments of the file it overwrites.

// commentedCentral is a hand-written central.yaml with a comment in every
// position the seal historically ate (top-of-file, head, trailing,
// standalone between list items, inside the global obf block down to
// individual strategy entries).
func commentedCentral(t *testing.T) (string, NyPrivateKey, string) {
	t.Helper()
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
	return central, key, pubText(pub)
}

// TestBundleConfigStripsComments pins the seal half of the contract: the
// distributed central.nybundle carries clean config — none of the raw
// file's comments survive into the sealed plaintext — while the values
// and the live-config property (strict re-parse, fresh timestamp) do.
func TestBundleConfigStripsComments(t *testing.T) {
	central, key, pubText := commentedCentral(t)

	bundle, err := BundleConfig(central, key)
	if err != nil {
		t.Fatalf("BundleConfig: %v", err)
	}

	text, cfg, err := UnbundleConfigText(bundle, key.Pubkey())
	if err != nil {
		t.Fatalf("UnbundleConfigText: %v", err)
	}

	// every comment position must be GONE from the sealed plaintext
	stripped := []string{
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
	for _, w := range stripped {
		if strings.Contains(text, w) {
			t.Errorf("comment %q leaked into the sealed bundle; plaintext:\n%s", w, text)
		}
	}
	if strings.Contains(text, "#") {
		t.Errorf("the sealed plaintext must be comment-free:\n%s", text)
	}

	// the values survive and the seal stamped a fresh timestamp
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

	// the sealed plaintext is live config: it re-parses strictly
	var round CentralCfg
	if err := yaml.UnmarshalWithOptions([]byte(text), &round, yaml.Strict()); err != nil {
		t.Fatalf("sealed plaintext does not re-parse strictly: %v\ntext:\n%s", err, text)
	}
	if len(round.Routers) != 2 || round.Routers[0].Id != "hub" || len(round.Routers[0].Endpoints) != 2 {
		t.Errorf("routers lost through the seal: %+v", round.Routers)
	}
	_ = pubText
}

// TestBundleConfigCommentFreeConfigUnchanged pins that a config without
// comments seals exactly as before (no stray artefacts) and the bundle
// still round-trips.
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
		t.Errorf("comment-free config gained artefacts:\n%s", text)
	}
	if len(cfg.Routers) != 1 || cfg.Routers[0].Id != "a" {
		t.Errorf("round-trip lost the router: %+v", cfg.Routers)
	}
}

// TestMarshalPreservingComments pins the daemon half of the contract: the
// local central.yaml refresh (poll writeback, startup fetch) re-renders the
// new config with the comments of the file it overwrites — the values
// change, the operator's documentation must not.
func TestMarshalPreservingComments(t *testing.T) {
	central, key, pubText := commentedCentral(t)

	// the "new config" is the raw central re-sealed (fresh timestamp), as
	// the poll path delivers it
	bundle, err := BundleConfig(central, key)
	if err != nil {
		t.Fatalf("BundleConfig: %v", err)
	}
	_, fresh, err := UnbundleConfigText(bundle, key.Pubkey())
	if err != nil {
		t.Fatalf("UnbundleConfigText: %v", err)
	}

	dir := t.TempDir()
	cachePath := filepath.Join(dir, "central.yaml")
	if err := os.WriteFile(cachePath, []byte(central), 0600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	out := MarshalPreservingComments(fresh, cachePath)
	if out == nil {
		t.Fatalf("MarshalPreservingComments returned nil")
	}
	s := string(out)
	for _, w := range []string{
		"# top-of-file comment",
		"# trailing on the dist key",
		"# standalone between top-level keys",
		"# the named strategy map",
		"# the strategy name is its identity",
		"# required: one port or a range",
		"# trailing on a map inside a list",
		"# standalone before the last list item",
	} {
		if !strings.Contains(s, w) {
			t.Errorf("comment %q did not survive the cache refresh; output:\n%s", w, s)
		}
	}
	// the refreshed file is live config: the fresh values, strictly parseable
	var re CentralCfg
	if err := yaml.UnmarshalWithOptions(out, &re, yaml.Strict()); err != nil {
		t.Fatalf("refreshed cache does not re-parse strictly: %v\n%s", err, s)
	}
	if re.Timestamp != fresh.Timestamp {
		t.Errorf("refreshed cache lost the fresh timestamp: %d vs %d", re.Timestamp, fresh.Timestamp)
	}

	// a path with no existing file: plain comment-free marshal (the
	// first-fetch bootstrap write)
	out = MarshalPreservingComments(fresh, filepath.Join(dir, "absent.yaml"))
	if out == nil || strings.Contains(string(out), "#") {
		t.Errorf("absent existing file must yield a plain marshal:\n%s", out)
	}

	// a stale existing file that does not even parse: plain marshal (the
	// comments of a file this binary cannot read are not the operator's to
	// keep — it is a cache being replaced)
	stalePath := filepath.Join(dir, "stale.yaml")
	if err := os.WriteFile(stalePath, []byte(":: not yaml [\n"), 0600); err != nil {
		t.Fatalf("write stale: %v", err)
	}
	out = MarshalPreservingComments(fresh, stalePath)
	if out == nil || strings.Contains(string(out), "#") {
		t.Errorf("broken existing file must yield a plain marshal:\n%s", out)
	}

	// a stale existing file carrying LEGACY keys this binary does not
	// model (strict-decode would fail) still contributes its comments —
	// the capture decode is deliberately lenient
	legacyPath := filepath.Join(dir, "legacy.yaml")
	legacy := strings.Replace(central, "obf:", "legacy_removed_section: true\nobf:", 1)
	if err := os.WriteFile(legacyPath, []byte(legacy), 0600); err != nil {
		t.Fatalf("write legacy: %v", err)
	}
	out = MarshalPreservingComments(fresh, legacyPath)
	if out == nil || !strings.Contains(string(out), "# top-of-file comment") {
		t.Errorf("a legacy-shaped cache must still contribute its comments:\n%s", out)
	}

	_ = pubText
}
