//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/encodeous/nylon/state"
	"github.com/goccy/go-yaml"
)

// obfFixture mirrors the nylon-genesis output fragment so the committed
// fixture (e2e/testdata/obf-profile.yaml) round-trips into the obf fields of
// state.CentralCfg: the global obf block — the mesh-wide S/H dialect inline
// plus ONE named strategy under `strategy:` carrying the sender-local junk
// (jc/jmin/jmax and i1-i5).
type obfFixture struct {
	Obf *state.CentralObf `yaml:"obf"`
}

// TestObfProfileConnectivity proves that two nylon nodes with a generated
// AWG 2.0 obfuscation fragment (mesh-wide S/H dialect + one named strategy
// carrying the sender-local junk) establish a mesh and pass traffic over the
// obfuscated wire format.
func TestObfProfileConnectivity(t *testing.T) {
	t.Parallel()
	h := NewHarness(t)

	// Load the committed fixture, generated once via:
	//   go run ./cmd/nylon-genesis --preset standard-1420 --protocol quic \
	//       --mtu 1420 --strategy-ports 51820
	fixturePath := filepath.Join(h.RootDir, "e2e", "testdata", "obf-profile.yaml")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading obf fixture: %v", err)
	}
	var fixture obfFixture
	if err := yaml.UnmarshalWithOptions(data, &fixture, yaml.Strict()); err != nil {
		t.Fatalf("parsing obf fixture: %v", err)
	}
	if fixture.Obf == nil {
		t.Fatal("obf fixture carries no global obf block")
	}
	if err := fixture.Obf.Validate(); err != nil {
		t.Fatalf("obf fixture profile invalid: %v", err)
	}
	if len(fixture.Obf.Strategy) != 1 {
		t.Fatalf("obf fixture must carry exactly one strategy, got %d", len(fixture.Obf.Strategy))
	}
	var strategyName string
	var strat *state.ObfStrategy
	for n, s := range fixture.Obf.Strategy {
		strategyName, strat = n, s
	}
	if strategyName == "" || strat == nil || strat.Ports == "" {
		t.Fatal("obf fixture strategy missing or unnamed")
	}

	// Generate keys
	node1Key := state.GenerateKey()
	node2Key := state.GenerateKey()

	// IPs in the docker network
	node1IP := GetIP(h.Subnet, 10)
	node2IP := GetIP(h.Subnet, 11)

	// Internal Nylon IPs
	node1NylonIP := "10.0.0.1"
	node2NylonIP := "10.0.0.2"

	// Create config directory for this test run
	configDir := h.SetupTestDir()

	// 1. Create Central Config: the mesh-wide S/H dialect plus the named
	// strategy carrying the sender-local junk. node2 advertises the
	// strategy (host[<strategy>]), so it serves the strategy's ports, and
	// every node in the graph draws the same effective junk configuration.
	router1 := SimpleRouter("node1", node1Key.Pubkey(), node1NylonIP, "")
	router2 := SimpleRouter("node2", node2Key.Pubkey(), node2NylonIP, "")
	router2.Endpoints = []string{fmt.Sprintf("%s[%s]", node2IP, strategyName)}
	central := state.CentralCfg{
		Routers: []state.RouterCfg{
			router1,
			router2,
		},
		Graph: []string{
			"node1, node2",
		},
		Timestamp: time.Now().UnixNano(),
		Obf:       fixture.Obf,
	}

	centralPath := h.WriteConfig(configDir, "central.yaml", central)

	// 2. Create Node Configs
	node1Cfg := SimpleLocal("node1", node1Key)
	node1Path := h.WriteConfig(configDir, "node1.yaml", node1Cfg)

	node2Cfg := SimpleLocal("node2", node2Key)
	node2Path := h.WriteConfig(configDir, "node2.yaml", node2Cfg)

	// 3. Start Containers in Parallel
	h.StartNodes(
		NodeSpec{Name: "node1", IP: node1IP, CentralConfigPath: centralPath, NodeConfigPath: node1Path},
		NodeSpec{Name: "node2", IP: node2IP, CentralConfigPath: centralPath, NodeConfigPath: node2Path},
	)

	// 4. Wait for convergence: with a two-node graph each node announces its
	// own /32, so each peer installs the other's nylon address as a route.
	t.Log("Waiting for convergence...")
	h.WaitForMatch("node1", `installing new route.*prefix=10\.0\.0\.2`)
	h.WaitForMatch("node2", `installing new route.*prefix=10\.0\.0\.1`)

	// 5. Test Connectivity through the obfuscated profile.
	t.Logf("Pinging %s from node1...", node2NylonIP)
	stdout, stderr, err := h.Exec("node1", []string{"ping", "-c", "3", node2NylonIP})
	if err != nil {
		// A packet sealed with the pre-profile layout is misclassified and
		// dropped by the peer, then retransmitted — benign startup window
		// (design §2.4). Retry the ping once before declaring failure.
		t.Logf("First ping attempt failed (startup retransmit window?): %v", err)
		h.PrintLogs("node1")
		h.PrintLogs("node2")
		stdout, stderr, err = h.Exec("node1", []string{"ping", "-c", "3", node2NylonIP})
		if err != nil {
			h.PrintLogs("node1")
			h.PrintLogs("node2")
			t.Fatalf("Ping failed after retry: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
		}
	}
	t.Logf("Ping output:\n%s", stdout)
}
