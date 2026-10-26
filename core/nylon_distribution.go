package core

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"time"

	"github.com/encodeous/nylon/state"
	"github.com/goccy/go-yaml"
)

// configFetchTimeout bounds a single config repo fetch. Without it a
// half-open server connection would pin one goroutine per poll round
// forever. It is intentionally larger than the default poll interval so a
// slow-but-alive repo still succeeds; rounds may overlap while a fetch is in
// flight, which is harmless (each repo fetch is a separate goroutine).
const configFetchTimeout = 30 * time.Second

// fetches and unbundles central config from url
func FetchConfig(repoStr string, key state.NyPublicKey, maxSize int64) (*state.CentralCfg, error) {
	return fetchConfig(repoStr, key, maxSize, state.NewDNSResolver(nil))
}

func fetchConfig(repoStr string, key state.NyPublicKey, maxSize int64, resolver *state.DNSResolver) (*state.CentralCfg, error) {
	repo, err := url.Parse(repoStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repo URL %s: %w", repoStr, err)
	}
	cfgBody := make([]byte, 0)

	switch repo.Scheme {
	case "file":
		file, err := os.ReadFile(repo.Opaque)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", repo.Opaque, err)
		}
		cfgBody = file
	case "http", "https":
		transport := &http.Transport{
			DialContext: resolver.DialContext,
		}
		client := &http.Client{
			Timeout:   configFetchTimeout,
			Transport: transport,
		}
		res, err := client.Get(repo.String())
		// the transport is per-fetch; release pooled idle connections
		// right away instead of waiting for the garbage collector
		defer transport.CloseIdleConnections()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch %s: %w", repo.String(), err)
		}
		cfgBody, err = io.ReadAll(io.LimitReader(res.Body, maxSize))
		if err != nil {
			_ = res.Body.Close()
			return nil, fmt.Errorf("failed to read response from %s: %w", repo.String(), err)
		}
		err = res.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to close response from %s: %w", repo.String(), err)
		}
	}

	config, err := state.UnbundleConfig(string(cfgBody), key)
	if err != nil {
		return nil, fmt.Errorf("failed to unbundle config from %s: %w", repoStr, err)
	}
	return config, nil
}

// responsible for central config distribution
func checkForConfigUpdates(n *Nylon) error {
	if n.CentralCfg.Dist == nil {
		return errors.New("nylon is not configured for automatic config distribution")
	}
	delay, source := n.pollDelay()
	n.Log.Info("checking config sources for updates",
		"repos", len(n.CentralCfg.Dist.Repos),
		"interval", delay.String(),
		"interval_source", source)
	key := n.CentralCfg.Dist.Key
	currentTimestamp := n.Timestamp
	repos := slices.Clone(n.CentralCfg.Dist.Repos)
	for _, repoStr := range repos {
		go func(repo string) {
			err := func() error {
				config, err := fetchConfig(repo, key, n.MaxConfigSize, n.DNSResolver)
				if err != nil {
					return err
				}
				if config.Timestamp <= currentTimestamp {
					// Info on purpose: an unchanged bundle is the
					// number one cause of "my interval / repo
					// edit changed nothing" (missing re-seal or
					// re-upload), and the timestamps make it
					// obvious on sight
					n.Log.Info("config bundle is not newer than the active config, skipping",
						"repo", repo,
						"bundle_timestamp", config.Timestamp,
						"active_timestamp", currentTimestamp)
					if n.DBG_log_repo_updates {
						n.Log.Debug(fmt.Sprintf("found old update bundle at %s, skipping", repo))
					}
					return nil
				}
				n.Dispatch(func() error {
					if config.Timestamp <= n.Timestamp {
						return nil
					}
					n.Log.Info("Found a new config update in repo", "repo", repo)
					result, err := n.ApplyCentralConfig(config)
					if err != nil {
						if result != ApplyApplied {
							n.Log.Error("failed to apply central config update", "repo", repo, "result", result, "err", err)
							return nil
						}
						n.Log.Warn("central config applied with incomplete runtime reconciliation; will retry", "repo", repo, "err", err)
					}
					if n.ConfigPath != "" {
						bytes, err := yaml.Marshal(config)
						if err != nil {
							n.Log.Error("Error marshalling new config", "err", err.Error())
							return nil
						}
						err = os.WriteFile(n.ConfigPath, bytes, 0600)
						if err != nil {
							n.Log.Error("Error writing new config", "err", err.Error())
						}
					}
					return nil
				})
				return nil
			}()
			if err != nil {
				n.Log.Error("failed to fetch config update",
					"repo", repo, "err", err.Error())
			}
		}(repoStr)
	}
	return nil
}

// configUpdateLoop polls the distribution repos for config updates. Unlike a
// RepeatTask ticker, the delay is re-resolved every round from the current
// configuration (central dist interval > node.yaml dist interval > tunables
// default), so updating dist.interval in a distributed config applies live,
// without a restart.
func (n *Nylon) configUpdateLoop() {
	delay, source := n.pollDelay()
	n.Log.Info("config poll loop started",
		"interval", delay.String(),
		"interval_source", source,
		"repos", len(n.CentralCfg.Dist.Repos))
	lastDelay, lastSource := delay, source
	n.Dispatch(func() error { return checkForConfigUpdates(n) })
	for n.Context.Err() == nil {
		timer := time.NewTimer(delay)
		select {
		case <-n.Context.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay, source = n.pollDelay()
		if delay != lastDelay || source != lastSource {
			n.Log.Info("config poll interval changed",
				"from", lastDelay.String(),
				"to", delay.String(),
				"interval_source", source)
			lastDelay, lastSource = delay, source
		}
		n.Dispatch(func() error { return checkForConfigUpdates(n) })
	}
}

// pollDelay resolves the current config polling cadence together with the
// configuration level it was taken from.
func (n *Nylon) pollDelay() (time.Duration, string) {
	return state.ResolveUpdateDelaySource(n.CentralCfg.Dist, n.LocalCfg.Dist, n.CentralUpdateDelay)
}
