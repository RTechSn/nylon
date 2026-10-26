package core

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/encodeous/nylon/state"
	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lockedBuffer makes a bytes.Buffer usable as a slog destination from the
// several goroutines that participate in a poll round (dispatch loop, repo
// fetch goroutine, poll loop).
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// waitForLog polls the buffer until substrings appear or the deadline hits.
func waitForLog(t *testing.T, lb *lockedBuffer, timeout time.Duration, subs ...string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out := lb.String()
		all := true
		for _, s := range subs {
			if !strings.Contains(out, s) {
				all = false
				break
			}
		}
		if all {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for log lines %v; journal so far:\n%s", subs, lb.String())
}

// serveBundle seals a minimal central config and serves it over HTTP.
func serveBundle(t *testing.T, key state.NyPrivateKey, repos []string) *httptest.Server {
	t.Helper()
	src, err := yaml.Marshal(&state.CentralCfg{
		Dist: &state.DistributionCfg{Key: key.Pubkey(), Repos: repos},
	})
	require.NoError(t, err)
	bundle, err := state.BundleConfig(string(src), key)
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(bundle))
	}))
	t.Cleanup(server.Close)
	return server
}

func newDistTestNylon(t *testing.T, lb *lockedBuffer) *Nylon {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(nil) })
	n := &Nylon{
		Log:             slog.New(slog.NewTextHandler(lb, nil)),
		DispatchChannel: make(chan func() error, 128),
		Context:         ctx,
		Cancel:          cancel,
		DNSResolver:     state.NewDNSResolver(nil),
	}
	n.RouterTunables = state.DefaultRouterTunables()
	return n
}

// The poll attempt itself must be visible in the journal, including the
// effective interval and where it came from - a silently ignored interval
// (e.g. one sealed into the bundle by an older binary) must be diagnosable.
func TestCheckForConfigUpdatesLogsAttempt(t *testing.T) {
	var lb lockedBuffer
	n := newDistTestNylon(t, &lb)
	server := serveBundle(t, state.GenerateKey(), nil)

	n.ConfigState.CentralCfg = state.CentralCfg{
		Timestamp: time.Now().UnixNano(),
		Dist: &state.DistributionCfg{
			Key:   state.GenerateKey().Pubkey(),
			Repos: []string{server.URL},
		},
	}

	require.NoError(t, checkForConfigUpdates(n))
	waitForLog(t, &lb, 2*time.Second,
		"checking config sources for updates",
		"interval=10s",
		"interval_source=default")
}

// A fetched bundle that is not newer than the active config is the number one
// cause of "my config edit changed nothing" (missing re-seal/re-upload), so
// the skip must be visible at Info with both timestamps.
func TestCheckForConfigUpdatesLogsStaleBundle(t *testing.T) {
	var lb lockedBuffer
	n := newDistTestNylon(t, &lb)
	key := state.GenerateKey()
	server := serveBundle(t, key, nil)

	n.ConfigState.CentralCfg = state.CentralCfg{
		// newer than the freshly sealed bundle -> stale
		Timestamp: time.Now().UnixNano(),
		Dist: &state.DistributionCfg{
			Key:   key.Pubkey(),
			Repos: []string{server.URL},
		},
	}

	require.NoError(t, checkForConfigUpdates(n))
	waitForLog(t, &lb, 2*time.Second,
		"config bundle is not newer than the active config, skipping",
		"repo="+server.URL)
	out := lb.String()
	assert.Contains(t, out, "bundle_timestamp=", "stale skip must log the bundle timestamp")
	assert.Contains(t, out, "active_timestamp=", "stale skip must log the active timestamp")
}

// Fetch failures must name the repo they failed on.
func TestCheckForConfigUpdatesLogsFetchError(t *testing.T) {
	var lb lockedBuffer
	n := newDistTestNylon(t, &lb)
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead.Close()

	n.ConfigState.CentralCfg = state.CentralCfg{
		Dist: &state.DistributionCfg{
			Key:   state.GenerateKey().Pubkey(),
			Repos: []string{dead.URL},
		},
	}

	require.NoError(t, checkForConfigUpdates(n))
	waitForLog(t, &lb, 2*time.Second,
		"failed to fetch config update",
		"repo="+dead.URL)
}

// The poll loop must announce its cadence at startup and honour the node.yaml
// interval without a restart.
func TestConfigUpdateLoopStartsAndRepeatsAtNodeInterval(t *testing.T) {
	var lb lockedBuffer
	n := newDistTestNylon(t, &lb)
	key := state.GenerateKey()
	server := serveBundle(t, key, nil)

	interval := 25 * time.Millisecond
	n.ConfigState.CentralCfg = state.CentralCfg{
		Timestamp: time.Now().UnixNano(),
		Dist: &state.DistributionCfg{
			Key:   key.Pubkey(),
			Repos: []string{server.URL},
		},
	}
	n.ConfigState.LocalCfg = state.LocalCfg{
		Dist: &state.LocalDistributionCfg{Interval: &interval},
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		n.configUpdateLoop()
	}()

	// drain the dispatch loop exactly like mainLoop would
	attempts := 0
	drained := func() bool {
		select {
		case f := <-n.DispatchChannel:
			if err := f(); err != nil {
				t.Errorf("dispatched check error: %v", err)
			}
			return true
		default:
			return false
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if drained() {
			attempts++
		} else {
			select {
			case <-time.After(5 * time.Millisecond):
			case <-n.Context.Done():
			}
		}
		if attempts >= 3 {
			break
		}
	}
	n.Cancel(nil)
	wg.Wait()

	out := lb.String()
	assert.Contains(t, out, "config poll loop started", "loop must log its start")
	assert.Contains(t, out, fmt.Sprintf("interval=%s", interval.String()))
	assert.Contains(t, out, "interval_source=node")
	assert.GreaterOrEqual(t, attempts, 3, "loop must keep polling at the configured interval")
	assert.GreaterOrEqual(t, strings.Count(out, "checking config sources for updates"), 3,
		"every poll attempt must leave a journal record")
}
