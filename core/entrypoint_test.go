package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/encodeous/nylon/state"
	"github.com/goccy/go-yaml"
)

// yamlUnmarshalStrict decodes strictly (the startup contract: a key this
// binary does not model must fail the parse loudly).
func yamlUnmarshalStrict(b []byte, v any) error {
	return yaml.UnmarshalWithOptions(b, v, yaml.Strict())
}

// The startup config resolution contract (readCentralConfig):
//
//   - the dist links of node.yaml are read LENIENTLY (only dist + dns
//     resolvers are modelled — a stale local node.yaml cannot wedge the
//     bootstrap);
//   - when links exist, the latest published bundle is fetched and a
//     strictly newer bundle WINS over the local central.yaml, which is only
//     a cache: a stale cache that no longer parses under this binary must
//     not block startup while a fresh central is already published (the
//     binary-update scenario);
//   - the local cache still serves when the links are absent/unreachable
//     (offline start) and when the published bundle is not newer;
//   - the cache refresh preserves the comments of the file being
//     overwritten (it may be the operator's hand-written central.yaml);
//   - when nothing is runnable the error names BOTH causes.

// startupFixture builds a temp-dir distribution stand: a sealed bundle at
// repoPath (a file: repo) plus a node.yaml pointing at it.
type startupFixture struct {
	dir        string
	key        state.NyPrivateKey
	repoPath   string
	repoURL    string
	centralTxt func() string
}

func newStartupFixture(t *testing.T) *startupFixture {
	t.Helper()
	dir := t.TempDir()
	key := state.GenerateKey()
	pub := key.Pubkey()
	pubText := func(k state.NyPublicKey) string {
		b, err := k.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText: %v", err)
		}
		return string(b)
	}
	f := &startupFixture{dir: dir, key: key}
	f.centralTxt = func() string {
		return `dist:
  key: ` + pubText(pub) + `
  repos:
    - ` + f.repoURL + `
routers:
  - id: hub
    pubkey: ` + pubText(key.Pubkey()) + `
  - id: leaf
    pubkey: ` + pubText(state.GenerateKey().Pubkey()) + `
graph:
  - hub, leaf
`
	}
	f.repoPath = filepath.Join(dir, "central.nybundle")
	f.repoURL = "file:" + f.repoPath
	return f
}

// sealNow seals the fixture central and writes the bundle to the repo path.
func (f *startupFixture) sealNow(t *testing.T) {
	t.Helper()
	bundle, err := state.BundleConfig(f.centralTxt(), f.key)
	if err != nil {
		t.Fatalf("BundleConfig: %v", err)
	}
	if err := os.WriteFile(f.repoPath, []byte(bundle), 0600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
}

// nodeYaml writes a node.yaml with the given dist url ("" = no dist block).
func (f *startupFixture) nodeYaml(t *testing.T, repoURL string) string {
	t.Helper()
	pub := f.key.Pubkey()
	pubText := func(k state.NyPublicKey) string {
		b, err := k.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText: %v", err)
		}
		return string(b)
	}
	node := "id: hub\n"
	if repoURL != "" {
		node += "dist:\n  key: " + pubText(pub) + "\n  url: " + repoURL + "\n"
	}
	path := filepath.Join(f.dir, "node.yaml")
	if err := os.WriteFile(path, []byte(node), 0600); err != nil {
		t.Fatalf("write node.yaml: %v", err)
	}
	return path
}

// writeLocalCache writes the local central.yaml cache.
func (f *startupFixture) writeLocalCache(t *testing.T, central string) string {
	t.Helper()
	path := filepath.Join(f.dir, "central.yaml")
	if err := os.WriteFile(path, []byte(central), 0600); err != nil {
		t.Fatalf("write cache: %v", err)
	}
	return path
}

func (f *startupFixture) run(t *testing.T, centralPath, nodePath string) (*state.CentralCfg, string, error) {
	t.Helper()
	tun := state.DefaultRouterTunables()
	return readCentralConfig(centralPath, nodePath, &tun)
}

// TestStartupFetchesLatestAndRefreshesCache pins the primary flow: with dist
// links present, the latest bundle wins over an older local cache, and the
// cache is refreshed (comments preserved — the file may be the operator's
// hand-written, documented central.yaml).
func TestStartupFetchesLatestAndRefreshesCache(t *testing.T) {
	f := newStartupFixture(t)
	f.sealNow(t)
	nodePath := f.nodeYaml(t, f.repoURL)

	local := strings.Replace(f.centralTxt(), "graph:", "# the peering graph\ntimestamp: 1\ngraph:", 1)
	centralPath := f.writeLocalCache(t, local)

	cfg, info, err := f.run(t, centralPath, nodePath)
	if err != nil {
		t.Fatalf("readCentralConfig: %v", err)
	}
	if cfg.Timestamp <= 1 {
		t.Errorf("the fetched (newer) bundle must win, got timestamp %d", cfg.Timestamp)
	}
	if !strings.Contains(info, "dist (") {
		t.Errorf("info must name the dist source, got %q", info)
	}

	refreshed, err := os.ReadFile(centralPath)
	if err != nil {
		t.Fatalf("read refreshed cache: %v", err)
	}
	if !strings.Contains(string(refreshed), "# the peering graph") {
		t.Errorf("the cache refresh must preserve the comments of the file it overwrites:\n%s", refreshed)
	}
	if !strings.Contains(string(refreshed), "id: hub") {
		t.Errorf("the refreshed cache must carry the fresh values:\n%s", refreshed)
	}
	var re state.CentralCfg
	if err := yamlUnmarshalStrict(refreshed, &re); err != nil {
		t.Fatalf("refreshed cache must re-parse strictly: %v", err)
	}
	if re.Timestamp != cfg.Timestamp {
		t.Errorf("refreshed cache timestamp %d != active %d", re.Timestamp, cfg.Timestamp)
	}
}

// TestStartupStaleCacheBypassed pins the binary-update scenario: a local
// cache this binary cannot parse (a pre-update shape) must NOT wedge
// startup when a fresh, valid central is already published — the fetch wins
// and the stale cache is replaced.
func TestStartupStaleCacheBypassed(t *testing.T) {
	f := newStartupFixture(t)
	f.sealNow(t)
	nodePath := f.nodeYaml(t, f.repoURL)

	stale := f.centralTxt() + "\nlegacy_removed_section: true\n"
	centralPath := f.writeLocalCache(t, stale)

	cfg, info, err := f.run(t, centralPath, nodePath)
	if err != nil {
		t.Fatalf("a stale cache must not block startup when the dist serves a fresh bundle: %v", err)
	}
	if !strings.Contains(info, "bypassed") {
		t.Errorf("info must note the bypassed stale cache, got %q", info)
	}
	if cfg == nil || cfg.Timestamp == 0 {
		t.Errorf("the fetched config must serve, got %+v", cfg)
	}

	// the stale cache was replaced by the fresh one
	refreshed, err := os.ReadFile(centralPath)
	if err != nil {
		t.Fatalf("read refreshed cache: %v", err)
	}
	var re state.CentralCfg
	if err := yamlUnmarshalStrict(refreshed, &re); err != nil {
		t.Fatalf("the refreshed cache must parse under this binary: %v\n%s", err, refreshed)
	}
	if re.Timestamp != cfg.Timestamp {
		t.Errorf("refreshed cache timestamp %d != active %d", re.Timestamp, cfg.Timestamp)
	}
}

// TestStartupNotNewerBundleUsesLocal pins that an unchanged bundle never
// churns the local cache: the local file serves and is not rewritten.
func TestStartupNotNewerBundleUsesLocal(t *testing.T) {
	f := newStartupFixture(t)
	f.sealNow(t)

	// fetch once so the cache carries the bundle's exact timestamp
	nodePath := f.nodeYaml(t, f.repoURL)
	centralPath := f.writeLocalCache(t, f.centralTxt())
	cfg, _, err := f.run(t, centralPath, nodePath)
	if err != nil {
		t.Fatalf("readCentralConfig: %v", err)
	}

	before, err := os.ReadFile(centralPath)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	_, info, err := f.run(t, centralPath, nodePath)
	if err != nil {
		t.Fatalf("readCentralConfig (2nd): %v", err)
	}
	if !strings.Contains(info, "not newer") {
		t.Errorf("info must name the local source, got %q", info)
	}
	after, err := os.ReadFile(centralPath)
	if err != nil {
		t.Fatalf("read cache (2nd): %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("an unchanged bundle must not rewrite the local cache")
	}
	_ = cfg
}

// TestStartupNoLinksLocalServes pins the no-dist rig shape (the demo stand):
// no links → the local cache serves, unchanged.
func TestStartupNoLinksLocalServes(t *testing.T) {
	f := newStartupFixture(t)
	nodePath := f.nodeYaml(t, "")
	centralPath := f.writeLocalCache(t, f.centralTxt())

	before, _ := os.ReadFile(centralPath)
	cfg, info, err := f.run(t, centralPath, nodePath)
	if err != nil {
		t.Fatalf("readCentralConfig: %v", err)
	}
	if cfg == nil || len(cfg.Routers) != 2 {
		t.Errorf("the local cache must serve, got %+v", cfg)
	}
	if !strings.Contains(info, "no dist links") {
		t.Errorf("info must note the absent links, got %q", info)
	}
	after, _ := os.ReadFile(centralPath)
	if string(before) != string(after) {
		t.Errorf("no links must never rewrite the local cache")
	}
}

// TestStartupOfflineLocalServes pins the offline fallback: an unreachable
// repo (network down) falls back to the valid local cache with the fetch
// error carried in the info for the journal.
func TestStartupOfflineLocalServes(t *testing.T) {
	f := newStartupFixture(t)
	nodePath := f.nodeYaml(t, "file:"+filepath.Join(f.dir, "missing.nybundle"))
	centralPath := f.writeLocalCache(t, f.centralTxt())

	cfg, info, err := f.run(t, centralPath, nodePath)
	if err != nil {
		t.Fatalf("offline start must serve the local cache: %v", err)
	}
	if cfg == nil || len(cfg.Routers) != 2 {
		t.Errorf("the local cache must serve, got %+v", cfg)
	}
	if !strings.Contains(info, "dist fetch failed") {
		t.Errorf("info must carry the fetch error, got %q", info)
	}
}

// TestStartupNothingRunnable pins the combined failure: a stale cache AND
// an unreachable repo produce ONE error naming both causes (the operator
// sees what to fix).
func TestStartupNothingRunnable(t *testing.T) {
	f := newStartupFixture(t)
	nodePath := f.nodeYaml(t, "file:"+filepath.Join(f.dir, "missing.nybundle"))
	stale := f.centralTxt() + "\nlegacy_removed_section: true\n"
	centralPath := f.writeLocalCache(t, stale)

	_, _, err := f.run(t, centralPath, nodePath)
	if err == nil {
		t.Fatalf("nothing runnable must fail loudly")
	}
	msg := err.Error()
	if !strings.Contains(msg, "does not parse under this binary") {
		t.Errorf("the error must name the stale cache, got: %s", msg)
	}
	if !strings.Contains(msg, "dist fetch failed") {
		t.Errorf("the error must name the failed fetch, got: %s", msg)
	}
}

// TestStartupFirstFetchWritesCache pins the bootstrap-first flow: no local
// file at all + working links → the fetched config serves and the cache is
// created for the next (offline) start.
func TestStartupFirstFetchWritesCache(t *testing.T) {
	f := newStartupFixture(t)
	f.sealNow(t)
	nodePath := f.nodeYaml(t, f.repoURL)
	centralPath := filepath.Join(f.dir, "central.yaml")

	cfg, info, err := f.run(t, centralPath, nodePath)
	if err != nil {
		t.Fatalf("readCentralConfig: %v", err)
	}
	if cfg == nil || cfg.Timestamp == 0 {
		t.Errorf("the fetched config must serve, got %+v", cfg)
	}
	if !strings.Contains(info, "dist (") {
		t.Errorf("info must name the dist source, got %q", info)
	}
	written, err := os.ReadFile(centralPath)
	if err != nil {
		t.Fatalf("the cache must be written on first fetch: %v", err)
	}
	var re state.CentralCfg
	if err := yamlUnmarshalStrict(written, &re); err != nil {
		t.Fatalf("the written cache must parse strictly: %v", err)
	}
	if re.Timestamp != cfg.Timestamp {
		t.Errorf("cache timestamp %d != active %d", re.Timestamp, cfg.Timestamp)
	}
}

// TestStartupLenientLinkExtraction pins that link extraction reads ONLY the
// dist block: a node.yaml carrying legacy/unknown keys elsewhere still
// bootstraps the fetch (the full node.yaml parse + validation happens after
// the central is resolved, with loud migration errors of its own).
func TestStartupLenientLinkExtraction(t *testing.T) {
	f := newStartupFixture(t)
	f.sealNow(t)
	pub := f.key.Pubkey()
	pubText := func(k state.NyPublicKey) string {
		b, err := k.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText: %v", err)
		}
		return string(b)
	}
	// legacy node shape: a retired listen_ports key + an unknown section —
	// the links still extract and the fetch still serves
	node := `id: hub
listen_ports: 40000-50000
legacy_unknown_section:
  nested: true
dist:
  key: ` + pubText(pub) + `
  url: ` + f.repoURL + `
`
	nodePath := filepath.Join(f.dir, "node.yaml")
	if err := os.WriteFile(nodePath, []byte(node), 0600); err != nil {
		t.Fatalf("write node.yaml: %v", err)
	}
	centralPath := filepath.Join(f.dir, "central.yaml")

	cfg, info, err := f.run(t, centralPath, nodePath)
	if err != nil {
		t.Fatalf("link extraction must tolerate a legacy node.yaml: %v", err)
	}
	if cfg == nil || cfg.Timestamp == 0 {
		t.Errorf("the fetched config must serve, got %+v", cfg)
	}
	if !strings.Contains(info, "dist (") {
		t.Errorf("info must name the dist source, got %q", info)
	}
}

// TestStartupFileRepoAbsolutePath pins the file-repo URL forms: both the
// historical relative "file:..." (opaque) and the absolute "file:///..."
// (path) forms fetch the same bundle.
func TestStartupFileRepoAbsolutePath(t *testing.T) {
	f := newStartupFixture(t)
	f.sealNow(t)
	centralPath := filepath.Join(f.dir, "central.yaml")

	// "file:<abs>" (opaque form)
	nodePath := f.nodeYaml(t, f.repoURL)
	if _, info, err := f.run(t, centralPath, nodePath); err != nil || !strings.Contains(info, "dist (") {
		t.Fatalf("relative-ish file repo must fetch: %v (%q)", err, info)
	}
	os.Remove(centralPath)

	// "file://<abs>" (path form)
	nodePath = f.nodeYaml(t, "file://"+f.repoPath)
	cfg, info, err := f.run(t, centralPath, nodePath)
	if err != nil || !strings.Contains(info, "dist (") {
		t.Fatalf("absolute file repo must fetch: %v (%q)", err, info)
	}
	if cfg == nil || cfg.Timestamp == 0 {
		t.Errorf("the fetched config must serve, got %+v", cfg)
	}
}
