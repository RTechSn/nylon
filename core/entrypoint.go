package core

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime/trace"

	"github.com/encodeous/nylon/internal/buildinfo"
	"github.com/encodeous/nylon/internal/logging"
	"github.com/encodeous/nylon/state"
	"github.com/goccy/go-yaml"
)

func setupDebugging(log *slog.Logger, opts state.NylonOptions) (cleanup func()) {
	if opts.DBG_trace {
		f, err := os.Create("trace.out")
		if err != nil {
			log.Error("failed to create trace file", "error", err)
		} else if err := trace.Start(f); err != nil {
			log.Error("failed to start runtime trace", "error", err)
			_ = f.Close()
		} else {
			log.Info("runtime trace started", "path", "trace.out")
			cleanup = func() {
				trace.Stop()
				_ = f.Close()
			}
		}
	}
	if opts.DBG_debug {
		go func() {
			if err := http.ListenAndServe("0.0.0.0:6060", nil); err != nil {
				log.Warn("debug server failed", "error", err)
			}
		}()
	}
	return cleanup
}

// distLinks is the lenient bootstrap read of node.yaml: ONLY the
// distribution links (dist.url + dist.key) and the DNS resolvers. A binary
// update must not wedge a node on its own stale local files — the links are
// the one thing startup genuinely needs before the latest published config
// can be fetched, so everything else in node.yaml is deliberately not
// modelled here (unknown keys are ignored, foreign type errors in unrelated
// sections cannot break link extraction).
type distLinks struct {
	Dist         *state.LocalDistributionCfg `yaml:",omitempty"`
	DnsResolvers []string                    `yaml:"dns_resolvers,omitempty"`
}

// readDistLinks extracts the distribution links from node.yaml. Any failure
// (absent, unreadable, unparseable links) yields nil: startup then falls
// back to the local central.yaml alone, exactly as before.
func readDistLinks(nodePath string) *distLinks {
	file, err := os.ReadFile(nodePath)
	if err != nil {
		return nil
	}
	var links distLinks
	if err := yaml.Unmarshal(file, &links); err != nil {
		return nil
	}
	return &links
}

// readCentralConfig resolves the central configuration to start with.
//
// The links come first: when node.yaml carries distribution links, the
// latest published bundle is fetched and a strictly newer bundle wins — the
// local central.yaml is only a CACHE, and a cache that no longer parses
// under this binary (a stale shape from before the update) must not wedge
// startup while a fresh central is already published. The local file still
// serves when the links are absent or unreachable (offline start) and when
// the published bundle is not newer. The returned info string names the
// winning source (and any bypassed stale cache / fetch error) for the
// startup journal.
func readCentralConfig(centralPath, nodePath string, tunables *state.RouterTunables) (*state.CentralCfg, string, error) {
	var fetchNote string
	var fetched *state.CentralCfg
	links := readDistLinks(nodePath)
	if links != nil && links.Dist != nil && links.Dist.Url != "" {
		cfg, err := fetchConfig(
			links.Dist.Url,
			links.Dist.Key,
			tunables.MaxConfigSize,
			state.NewDNSResolver(links.DnsResolvers),
		)
		if err != nil {
			fetchNote = fmt.Sprintf("dist fetch failed: %v", err)
		} else {
			fetched = cfg
		}
	}

	var local *state.CentralCfg
	var localErr error
	file, err := os.ReadFile(centralPath)
	switch {
	case err == nil:
		cfg := &state.CentralCfg{}
		// Strict: a key the binary does not model must fail loudly, not
		// silently vanish from the parsed config (a dropped section is
		// indistinguishable from "applied" until traffic proves otherwise;
		// bundles keep the same guarantee via state.UnbundleConfig). A
		// strict failure here is NOT terminal — a fresh fetch may replace
		// the stale cache; it is fatal only when nothing else can run.
		if uerr := yaml.UnmarshalWithOptions(file, cfg, yaml.Strict()); uerr != nil {
			localErr = uerr
		} else {
			local = cfg
		}
	case os.IsNotExist(err):
		// no local cache; the fetch (if any) is the only candidate
	default:
		return nil, "", err
	}

	switch {
	case fetched != nil && (local == nil || fetched.Timestamp > local.Timestamp):
		info := "dist (" + links.Dist.Url + ")"
		if localErr != nil {
			info += "; the local cache did not parse under this binary and was bypassed"
		}
		// refresh the local cache so the next (offline) start has the
		// latest; the comments of the file being overwritten survive (it
		// may be the operator's hand-written central.yaml)
		bytes := state.MarshalPreservingComments(fetched, centralPath)
		if bytes != nil {
			if werr := os.WriteFile(centralPath, bytes, 0600); werr != nil {
				info += fmt.Sprintf("; cache write failed: %v", werr)
			}
		}
		return fetched, info, nil
	case fetched != nil:
		// the published bundle is not newer than the local cache
		return local, "local cache (the published bundle is not newer)", nil
	case local != nil:
		info := "local cache"
		if fetchNote != "" {
			info += " (" + fetchNote + ")"
		}
		if links != nil && links.Dist == nil {
			info += " (node.yaml has no dist links)"
		}
		return local, info, nil
	default:
		// nothing runnable: name both failure causes so the operator sees
		// why nothing can start and what to fix (cache or repo)
		switch {
		case localErr != nil && fetchNote != "":
			return nil, "", fmt.Errorf("the local central.yaml cache does not parse under this binary: %w; and fetching the latest config from the dist links failed: %s (update the local cache manually or restore the repo)", localErr, fetchNote)
		case localErr != nil:
			return nil, "", fmt.Errorf("the local central.yaml cache does not parse under this binary: %w; and node.yaml carries no usable dist links to fetch the latest published config (update the local cache manually)", localErr)
		case fetchNote != "":
			return nil, "", fmt.Errorf("central.yaml not found at %s and the dist fetch failed: %s", centralPath, fetchNote)
		default:
			return nil, "", fmt.Errorf("central.yaml not found and node.yaml has no dist config")
		}
	}
}

func readNodeConfig(nodePath string) (*state.LocalCfg, error) {
	var nodeCfg state.LocalCfg
	file, err := os.ReadFile(nodePath)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(file, &nodeCfg)
	if err != nil {
		return nil, err
	}
	return &nodeCfg, nil
}

func fatal(msg string, err error) {
	fmt.Fprintf(os.Stderr, "Error: %s: %v\n", msg, err)
	os.Exit(1)
}

// Bootstrap provides startup logic in a real environment
func Bootstrap(centralPath, nodePath, logPath string, level slog.Level, opts state.NylonOptions) {
	tunables := state.DefaultRouterTunables()
	centralCfg, centralInfo, err := readCentralConfig(centralPath, nodePath, &tunables)
	if err != nil {
		fatal("failed to read central config", err)
	}
	nodeCfg, err := readNodeConfig(nodePath)
	if err != nil {
		fatal("failed to read node config", err)
	}
	if logPath != "" {
		nodeCfg.LogPath = logPath
	}

	state.ExpandCentralConfig(centralCfg)
	if err = state.CentralConfigValidator(centralCfg); err != nil {
		fatal("invalid central config", err)
	}
	if err = state.NodeConfigValidator(centralCfg, nodeCfg); err != nil {
		fatal("invalid node config", err)
	}
	if nodeCfg.Tunables != nil {
		state.ApplyTunablesOverrides(&tunables, nodeCfg.Tunables)
	}

	logger, closer, err := logging.New(logging.Config{
		Component: "nylon",
		Node:      string(nodeCfg.Id),
		Level:     level,
		JSON:      opts.DBG_log_json,
		FilePath:  nodeCfg.LogPath,
	})
	if err != nil {
		fatal("failed to initialize logging", err)
	}
	defer closer()
	if cleanup := setupDebugging(logger, opts); cleanup != nil {
		defer cleanup()
	}

	logger.Info("starting nylon",
		"version", buildinfo.Version,
		"commit", buildinfo.Commit,
		"node", string(nodeCfg.Id),
		"interface", nodeCfg.InterfaceName,
		"central_config", centralPath,
		"central_config_source", centralInfo,
		"node_config", nodePath,
		"observability_addr", nodeCfg.ObservabilityAddr,
		"log_level", level.String(),
	)
	logger.Debug("effective tunables", "tunables", tunables)

	n, err := NewNylon(*centralCfg, *nodeCfg, logger, centralPath, nil, opts, &tunables)
	if err != nil {
		fatal("failed to initialize nylon", err)
	}
	if err = n.Start(); err != nil {
		fatal("nylon exited with error", err)
	}
}
