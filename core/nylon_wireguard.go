package core

import (
	"bufio"
	"cmp"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/polyamide/tun"
	"github.com/encodeous/nylon/state"
)

// resolveMTU returns the configured TUN MTU or the device default.
func resolveMTU(cfg *state.LocalCfg) int {
	if cfg.MTU != nil {
		return int(*cfg.MTU)
	}
	return device.DefaultMTU
}

// resolveTunOptions returns the configured TUN link options or the defaults.
func resolveTunOptions(cfg *state.LocalCfg) tun.CreateOptions {
	opts := tun.DefaultCreateOptions()
	if cfg.TunQueues != nil {
		opts.Queues = *cfg.TunQueues
	}
	if cfg.TunTxQueueLen != nil {
		opts.TxQueueLen = *cfg.TunTxQueueLen
	}
	if cfg.TunBackpressure != nil {
		opts.Backpressure = *cfg.TunBackpressure
	}
	return opts
}

// obfDeviceIPC renders the device-level AWG 2.0 UAPI knobs for the active
// central config. A nil profile yields the vanilla-compat default: AWG with
// every parameter unset picks message type 0 (PickOne over a zero range),
// which is NOT vanilla WireGuard — pinning H1..H4 to the WG message types
// preserves byte-level vanilla behavior for existing meshes and the
// version-skew window (design §2.4). The I-packet set is device-global — the
// AWG 2.0 device prepends it to every handshake toward every peer — so the
// strategies the node uses must agree on one i-set (state.
// EffectiveStrategyIPackets); the winning set's provider names itself in the
// journal.
func obfDeviceIPC(obf *state.ObfProfile, iSet [5]string) string {
	var b strings.Builder
	if obf == nil {
		b.WriteString("h1=1-1\nh2=2-2\nh3=3-3\nh4=4-4\n")
	} else {
		fmt.Fprintf(&b, "jc=%d\njmin=%d\njmax=%d\n", obf.Jc, obf.Jmin, obf.Jmax)
		fmt.Fprintf(&b, "s1=%d\ns2=%d\ns3=%d\ns4=%d\n", obf.S1, obf.S2, obf.S3, obf.S4)
		fmt.Fprintf(&b, "h1=%d-%d\n", obf.H1.Min, obf.H1.Max)
		fmt.Fprintf(&b, "h2=%d-%d\n", obf.H2.Min, obf.H2.Max)
		fmt.Fprintf(&b, "h3=%d-%d\n", obf.H3.Min, obf.H3.Max)
		fmt.Fprintf(&b, "h4=%d-%d\n", obf.H4.Min, obf.H4.Max)
	}
	for i, spec := range iSet {
		if spec != "" {
			fmt.Fprintf(&b, "i%d=%s\n", i+1, spec)
		}
	}
	return b.String()
}

// strategyIPacketSet resolves this node's effective junk-packet set from the
// obf strategies it uses (own + peers' advertised endpoints): at most one
// non-empty i-set may be in effect, since the device prepends it to every
// handshake toward every peer.
func (n *Nylon) strategyIPacketSet() ([5]string, []string, string, error) {
	used := state.NodeUsedStrategies(&n.CentralCfg, n.LocalCfg.Id)
	iSet, source, err := state.EffectiveStrategyIPackets(n.CentralCfg.ObfStrategies, used)
	if err != nil {
		return [5]string{}, nil, "", fmt.Errorf("obf strategies: %w", err)
	}
	return iSet, used, source, nil
}

// applyObfDeviceIPC (re-)applies the device-level AWG dialect and junk
// packets, journalling the effective state whenever it changes (startup,
// config update): the S/H/J profile, the strategy count and the i-set
// provider.
func (n *Nylon) applyObfDeviceIPC() error {
	iSet, used, source, err := n.strategyIPacketSet()
	if err != nil {
		return err
	}
	sig := fmt.Sprintf("%p|%v|%s", n.AwgProfile, used, source)
	if err := n.Device.IpcSet(obfDeviceIPC(n.AwgProfile, iSet)); err != nil {
		return fmt.Errorf("failed to apply obf profile: %v", err)
	}
	if sig != n.obfAppliedSig {
		n.obfAppliedSig = sig
		n.Log.Info("obf strategies applied",
			"strategies", len(n.CentralCfg.ObfStrategies),
			"used", len(used),
			"i-set", source)
	}
	return nil
}

// hopDeviceIPC renders the device-level port-hopping UAPI knob: the listen
// ranges (server half) derived from the obf strategies this node's own
// advertised endpoints name (merged, disjoint — see state.ListenUnionRanges).
// The client half (rotation budget) is applied per-peer through the hop
// controller, not through device UAPI. In listen_mode: nftables the ranges
// are served by the kernel redirect instead of per-port sockets, so the
// device is deliberately left unaware of them.
func (n *Nylon) hopDeviceIPC() (string, []state.PortRange, error) {
	ranges, err := n.listenUnionRanges()
	if err != nil {
		return "", nil, err
	}
	var b strings.Builder
	if len(ranges) > 0 && !n.LocalCfg.UsesNftListenMode() {
		fmt.Fprintf(&b, "listen_ports=%s\n", state.RangesString(ranges))
	}
	return b.String(), ranges, nil
}

// listenUnionRanges derives this node's server-side listen union from the
// obf strategies its own advertised endpoints name (untagged = all).
func (n *Nylon) listenUnionRanges() ([]state.PortRange, error) {
	if len(n.CentralCfg.ObfStrategies) == 0 {
		return nil, nil
	}
	var mine *state.RouterCfg
	if n.CentralCfg.IsRouter(n.LocalCfg.Id) {
		r := n.CentralCfg.GetRouter(n.LocalCfg.Id)
		mine = &r
	}
	return state.ListenUnionRanges(mine, n.CentralCfg.ObfStrategies)
}

// installNftRedirect installs the daemon-owned netfilter redirect serving the
// listen range on the primary port and remembers it for shutdown removal.
// Callers make a failure here fatal (see initWireGuard).
func (n *Nylon) installNftRedirect(prs []state.PortRange) error {
	r := newNftRangeRedirects(n.Port, prs)
	if err := r.Install(); err != nil {
		return err
	}
	n.nftRedirect = r
	return nil
}

// applyListenIPC applies the strategy-derived listen union live when it
// changed since the last apply (initWireGuard seeds the first one through
// hopDeviceIPC): sockets mode re-renders the device UAPI knob, nftables mode
// reinstalls the redirect table wholesale. Idempotent when nothing moved.
func (n *Nylon) applyListenIPC() error {
	if n.Device == nil {
		return nil
	}
	ranges, err := n.listenUnionRanges()
	if err != nil {
		return err
	}
	sig := n.LocalCfg.EffectiveListenMode() + "|" + state.RangesString(ranges)
	if sig == n.listenAppliedSig {
		return nil
	}
	n.listenAppliedSig = sig
	if n.LocalCfg.UsesNftListenMode() {
		if len(ranges) == 0 {
			// the union emptied (all strategy endpoints removed):
			// drop the redirect so the table stops shadowing
			if n.nftRedirect != nil {
				if err := n.nftRedirect.Remove(); err != nil {
					n.Log.Warn("failed to remove the nftables redirect for an empty listen union", "error", err)
				}
				n.nftRedirect = nil
			}
			return nil
		}
		if err := n.installNftRedirect(ranges); err != nil {
			return fmt.Errorf("listen_mode: nftables failed to serve the strategy listen union %s: %v", state.RangesString(ranges), err)
		}
		return nil
	}
	if len(ranges) == 0 {
		return nil // nothing to bind beyond the primary port
	}
	if err := n.Device.IpcSet(fmt.Sprintf("listen_ports=%s\n", state.RangesString(ranges))); err != nil {
		return fmt.Errorf("failed to apply the listen union: %v", err)
	}
	return nil
}

func (n *Nylon) initWireGuard() error {
	dev, tdev, itfName, err := NewWireGuardDevice(n)
	if err != nil {
		return err
	}

	err = dev.Up()
	if err != nil {
		return err
	}

	n.Device = dev
	n.Tun = tdev
	n.Interface = itfName

	n.InstallTC()
	n.Log.Info("installed nylon traffic control filter for polysock")

	dev.IpcHandler["get=nylon\n"] = func(writer *bufio.ReadWriter) error {
		return HandleNylonIPC(n, writer)
	}

	hopIPC, listenRanges, err := n.hopDeviceIPC()
	if err != nil {
		return err
	}

	// TODO: fully convert to code-based api
	err = dev.IpcSet(
		fmt.Sprintf(
			`private_key=%s
listen_port=%d
`,
			hex.EncodeToString(n.Key[:]),
			n.Port,
		) + hopIPC,
	)
	if err != nil {
		return fmt.Errorf("failed to configure wg device: %v", err)
	}
	if err := n.applyObfDeviceIPC(); err != nil {
		return err
	}

	// Surface the strategy-derived listen union at the default log level.
	// A hopping server that silently lost its ranges (a binary built
	// before this feature, an overwritten central config) is otherwise
	// indistinguishable from a healthy single-port node: the daemon
	// starts fine and the client just rotates through dead ports forever.
	if len(listenRanges) > 0 {
		ports := 0
		for _, pr := range listenRanges {
			ports += pr.Size()
		}
		if n.LocalCfg.UsesNftListenMode() {
			// daemon-managed netfilter redirect: single socket, the kernel
			// rewrites the union onto the primary port. A failure here is
			// fatal by design — same contract as the socket range listener,
			// the daemon refuses to run with a half-served union.
			if err := n.installNftRedirect(listenRanges); err != nil {
				return fmt.Errorf("listen_mode: nftables failed to serve the strategy listen union %s: %v", state.RangesString(listenRanges), err)
			}
			n.Log.Info("obf strategy listen union served by nftables redirect",
				"listen_ports", state.RangesString(listenRanges),
				"ports", ports,
				"primary_port", n.Port,
				"table", "inet "+NftTableName,
			)
		} else {
			n.Log.Info("obf strategy range listener active",
				"listen_ports", state.RangesString(listenRanges),
				"ports", ports,
				"primary_port", n.Port,
			)
		}
	}

	// add peers
	n.listenAppliedSig = n.LocalCfg.EffectiveListenMode() + "|" + state.RangesString(listenRanges)
	err = n.SyncWireGuard()
	if err != nil {
		return err
	}

	// configure system networking

	// run pre-up commands
	for _, cmd := range n.PreUp {
		err = ExecSplit(n.Log, cmd)
		if err != nil {
			n.Log.Error("failed to run pre-up command", "err", err)
		}
	}

	if !n.NoNetConfigure && !n.NoTun {
		for _, addr := range n.GetRouter(n.LocalCfg.Id).Addresses {
			err := ConfigureAlias(n.Log, itfName, addr)
			if err != nil {
				n.Log.Error("failed to configure alias", "err", err)
			} else if !slices.Contains(n.AppliedSystem.Aliases, addr) {
				n.AppliedSystem.Aliases = append(n.AppliedSystem.Aliases, addr)
			}
		}

		err = InitInterface(n.Log, itfName)
		if err != nil {
			return err
		}
	}

	// run post-up commands
	for _, cmd := range n.PostUp {
		err = ExecSplit(n.Log, cmd)
		if err != nil {
			n.Log.Error("failed to run post-up command", "err", err)
		}
	}

	// schedule application state reconciliation: the periodic tick re-applies
	// wireguard endpoints and recomputes routes, then hands the OS-level route
	// and alias programming to the applier goroutine
	n.RepeatTask(func() error {
		if err := n.SyncApplicationState(); err != nil {
			n.Log.Warn("runtime reconciliation incomplete; will retry", "err", err)
		}
		return nil
	}, n.ProbeDelay)

	n.startTunStatsPolling()

	return nil
}

func (n *Nylon) cleanupWireGuard() error {
	// remove routes
	for _, route := range n.AppliedSystem.Routes {
		err := RemoveRoute(n.Log, n.Tun, n.Interface, route)
		if err != nil {
			n.Log.Error("failed to remove route", "err", err)
		}
	}
	for _, addr := range n.AppliedSystem.Aliases {
		err := RemoveAlias(n.Log, n.Interface, addr)
		if err != nil {
			n.Log.Error("failed to remove alias", "err", err)
		}
	}
	// run pre-down commands
	for _, cmd := range n.PreDown {
		err := ExecSplit(n.Log, cmd)
		if err != nil {
			n.Log.Error("failed to run pre-down command", "err", err)
		}
	}
	err := CleanupWireGuardDevice(n)
	if err != nil {
		return err
	}
	// run post-down commands
	for _, cmd := range n.PostDown {
		err = ExecSplit(n.Log, cmd)
		if err != nil {
			n.Log.Error("failed to run post-down command", "err", err)
		}
	}
	return nil
}

func (n *Nylon) SyncWireGuard() error {
	if n.Device == nil {
		return nil
	}
	if n.AppliedSystem.Peers == nil {
		n.AppliedSystem.Peers = make(map[state.NodeId]state.NyPublicKey)
	}

	// (re-)apply the AWG 2.0 obfuscation knobs; a config reload may switch the
	// S/H profile or the effective i-set live. In-flight handshakes can fail
	// for one rekey window — maintenance-action semantics (design §2.4).
	if err := n.applyObfDeviceIPC(); err != nil {
		return err
	}
	// a config reload may also move the strategy-derived listen union
	// (endpoints/strategies are central-side): apply it live when it
	// changed, the same maintenance-action semantics as the dialect.
	if err := n.applyListenIPC(); err != nil {
		return err
	}
	desired := make(map[state.NodeId]state.NyPublicKey)
	for _, peer := range n.GetPeers(n.Id) {
		ncfg := n.GetNode(peer)
		desired[peer] = ncfg.PubKey
	}

	// Prepare every desired peer before removing any old peer. In particular,
	// public-key rotation must keep the old peer alive until the forwarding
	// table has been rebound to the replacement.
	for _, peer := range slices.Sorted(slices.Values(n.GetPeers(n.Id))) {
		ncfg := n.GetNode(peer)
		wgPeer := n.Device.LookupPeer(device.NoisePublicKey(ncfg.PubKey))
		if wgPeer == nil {
			n.Log.Debug("adding", "peer", peer)
			var err error
			wgPeer, err = n.Device.NewPeer(device.NoisePublicKey(ncfg.PubKey))
			if err != nil {
				return err
			}
			wgPeer.Start()
		}
		if n.IsClient(peer) {
			wgPeer.SetPreferRoaming(true)
		}
	}

	if err := n.syncWireGuardEndpoints(); err != nil {
		return err
	}

	// The forwarding table caches concrete peers for the one-lookup hot path.
	// Rebind every entry before stopping peers from the previous generation.
	n.rebindForwardingPeers()

	desiredKeys := make(map[state.NyPublicKey]struct{}, len(desired))
	for _, key := range desired {
		desiredKeys[key] = struct{}{}
	}
	for _, wgPeer := range n.Device.GetPeers() {
		key := state.NyPublicKey(wgPeer.GetPublicKey())
		if _, ok := desiredKeys[key]; ok {
			continue
		}
		n.Log.Debug("removing obsolete WireGuard peer", "key", key)
		n.Device.RemovePeer(wgPeer.GetPublicKey())
	}

	n.AppliedSystem.Peers = desired
	return nil
}

func (n *Nylon) syncWireGuardEndpoints() error {
	if n.Device == nil {
		return nil
	}
	dev := n.Device

	// configure endpoints
	for _, peer := range slices.Sorted(slices.Values(n.GetPeers(n.Id))) {
		if n.IsClient(peer) {
			continue
		}
		pcfg := n.GetRouter(peer)
		nhNeigh := n.RouterState.GetNeighbour(peer)
		eps := make([]conn.Endpoint, 0)

		if nhNeigh != nil {
			links := slices.Clone(nhNeigh.Eps)
			slices.SortStableFunc(links, func(a, b state.Endpoint) int {
				return cmp.Compare(a.Metric(), b.Metric())
			})
			for _, ep := range links {
				// port hopping: burned (retired) ports must not receive
				// fresh handshake initiations — their links exist only for
				// late pongs and are removed after the tombstone grace.
				if ep.IsExhausted() {
					continue
				}
				nep, err := ep.AsNylonEndpoint().GetWgEndpoint(n.Device, n.EndpointResolver)
				if err != nil {
					continue
				}
				eps = append(eps, nep)
			}
		}

		wgPeer := dev.LookupPeer(device.NoisePublicKey(pcfg.PubKey))
		if wgPeer != nil {
			wgPeer.SetEndpoints(eps)
		}
	}

	return nil
}
