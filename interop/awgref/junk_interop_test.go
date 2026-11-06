//go:build awg_ref_interop

package awgref

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"

	refconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	refdev "github.com/amnezia-vpn/amneziawg-go/v3/device"
	reftuntest "github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/polyamide/tun/tuntest"
)

// dialectLines are the S/H handshake dialect lines only (knobLines minus the
// sender-local junk trio): the dialect is the wire contract both sides must
// share, the junk is sender-local — a stock receiver silently drops
// everything it cannot classify (polyamide/device/receive.go, the reference
// alike), so the reference needs no junk of its own to interop with ours.
const dialectLines = "s1=32\n" +
	"s2=28\n" +
	"s3=20\n" +
	"s4=16\n" +
	"h1=100-5000000\n" +
	"h2=10000000-200000000\n" +
	"h3=400000000-800000000\n" +
	"h4=1000000000-2100000000\n"

// peerJunkSource is the in-process per-peer junk hook (device.JunkSource)
// the nylon core installs on strategy-carried peers: a switchable spec, as
// the core serves the spec of the connection's CARRYING strategy (which
// changes with every rotation across strategies).
type peerJunkSource struct {
	mu   sync.Mutex
	spec device.JunkSpec
}

func (s *peerJunkSource) JunkFor(*device.Peer) (device.JunkSpec, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spec, true
}

func (s *peerJunkSource) set(spec device.JunkSpec) {
	s.mu.Lock()
	s.spec = spec
	s.mu.Unlock()
}

var _ device.JunkSource = (*peerJunkSource)(nil)

// handshakeSecs returns the peer's last handshake timestamp from a UAPI
// dump (0 = no handshake yet).
func handshakeSecs(t *testing.T, d ipcDevice, name string) uint64 {
	t.Helper()
	out, err := d.IpcGet()
	if err != nil {
		t.Fatalf("%s: IpcGet: %v", name, err)
	}
	var secs uint64
	for _, line := range strings.Split(out, "\n") {
		value, ok := strings.CutPrefix(line, "last_handshake_time_sec=")
		if !ok {
			continue
		}
		v, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			t.Fatalf("%s: bad last_handshake_time_sec %q: %v", name, value, err)
		}
		secs = v
	}
	return secs
}

// TestNylonPerPeerJunkSourceWithReference proves hook-driven junk is
// wire-equivalent to device-driven junk: a nylon device whose UAPI knobs
// carry NO junk at all (jc/jmin/jmax and i1..i5 all unset), with the
// handshake prepend stream supplied entirely by a per-peer junk source
// (device.JunkSource, what the nylon core installs for strategy-carried
// peers), completes the handshake and exchanges byte-identical data with
// the upstream reference — which drops the junk stream as unclassified, its
// stock behaviour. The spec is then SWITCHED live (the junk of a rotation
// across strategies): the WireGuard session survives the switch, data keeps
// flowing and no re-handshake happens.
func TestNylonPerPeerJunkSourceWithReference(t *testing.T) {
	nylonAddr := netip.MustParseAddr(nylonIP)
	refAddr := netip.MustParseAddr(refIP)

	nylonKey := genKeyPair(t)
	refKey := genKeyPair(t)

	nylonLevel, refLevel := device.LogLevelError, refdev.LogLevelError
	if testing.Verbose() {
		nylonLevel, refLevel = device.LogLevelVerbose, refdev.LogLevelVerbose
	}

	nylonTun := tuntest.NewChannelTUN()
	nylonDev := device.NewDevice(nylonTun.TUN(), conn.NewDefaultBind(), device.NewLogger(nylonLevel, "nylon: "))
	refTun := reftuntest.NewChannelTUN()
	refDev := refdev.NewDevice(refTun.TUN(), refconn.NewDefaultBind(), refdev.NewLogger(refLevel, "awgref: "))
	t.Cleanup(nylonDev.Close)
	t.Cleanup(refDev.Close)

	// The dialect lines only — the nylon device knobs stay junk-free (the
	// fallback renders nothing), so every junk byte on the wire must come
	// from the hook.
	nylonCfg := dialectLines + uapiCfg(
		"private_key", hex.EncodeToString(nylonKey.priv[:]),
		"listen_port", strconv.Itoa(nylonPort),
		"replace_peers", "true",
		"public_key", hex.EncodeToString(refKey.pub[:]),
		"replace_allowed_ips", "true",
		"allowed_ip", refAddr.String()+"/32",
		"endpoint", fmt.Sprintf("127.0.0.1:%d", refPort),
		"persistent_keepalive_interval", strconv.Itoa(keepaliveSecs),
	)
	refCfg := dialectLines + uapiCfg(
		"private_key", hex.EncodeToString(refKey.priv[:]),
		"listen_port", strconv.Itoa(refPort),
		"replace_peers", "true",
		"public_key", hex.EncodeToString(nylonKey.pub[:]),
		"replace_allowed_ips", "true",
		"allowed_ip", nylonAddr.String()+"/32",
		"endpoint", fmt.Sprintf("127.0.0.1:%d", nylonPort),
		"persistent_keepalive_interval", strconv.Itoa(keepaliveSecs),
	)

	if err := nylonDev.IpcSet(nylonCfg); err != nil {
		t.Fatalf("failed to configure nylon device: %v", err)
	}
	if err := refDev.IpcSet(refCfg); err != nil {
		t.Fatalf("failed to configure reference device: %v", err)
	}

	// Wire the per-peer junk hook BEFORE the first initiation: the spec a
	// strategy-carried connection speaks (a full trio plus i-packets — the
	// same shape the device knobs used to render in TestNylonAwgInterop-
	// WithReference, now served through the hook).
	src := &peerJunkSource{}
	src.set(device.JunkSpec{
		Jc:   5,
		Jmin: 250,
		Jmax: 800,
		I:    [5]string{"<b 0xc0ff>", "", "<r 16>", "", ""},
	})
	nylonPeer := nylonDev.LookupPeer(device.NoisePublicKey(refKey.pub))
	if nylonPeer == nil {
		t.Fatal("nylon peer missing after configuration")
	}
	nylonPeer.SetJunkSource(src)

	// The hook — not the knobs — owns the wire junk: the dump must show the
	// per-peer spec with NO device-level junk configured.
	dump, err := nylonDev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	for _, forbidden := range []string{"\njc=", "\njmin=", "\njmax=", "\ni1=", "\ni2=", "\ni3=", "\ni4=", "\ni5="} {
		if strings.Contains(dump, forbidden) {
			t.Fatalf("the device knobs must stay junk-free (the hook owns the wire junk); dump carries %q:\n%s", strings.TrimSpace(forbidden), dump)
		}
	}
	for _, want := range []string{"junk_hook=true\n", "junk_jc=5\n", "junk_jmin=250\n", "junk_jmax=800\n", "junk_i1=<b 0xc0ff>\n", "junk_i3=<r 16>\n"} {
		if !strings.Contains(dump, want) {
			t.Fatalf("the dump must surface the hook spec; missing %q:\n%s", want, dump)
		}
	}

	if err := nylonDev.Up(); err != nil {
		t.Fatalf("failed to bring up nylon device: %v", err)
	}
	if err := refDev.Up(); err != nil {
		t.Fatalf("failed to bring up reference device: %v", err)
	}

	// Flush the pre-profile TUN readers with unrouted sacrificial packets
	// (see TestNylonAwgInteropWithReference).
	unrouted := netip.MustParseAddr("9.9.9.9")
	nylonTun.Outbound <- tuntest.Ping(unrouted, nylonAddr)
	refTun.Outbound <- reftuntest.Ping(unrouted, refAddr)

	// The sacrificial outbound packet makes the nylon side initiate — the
	// initiation rides jc=5 junk + 2 i-packets, all hook-supplied.
	nylonTun.Outbound <- tuntest.Ping(refAddr, nylonAddr)

	waitForHandshake(t, nylonDev, "nylon")
	waitForHandshake(t, refDev, "awgref")
	t.Log("handshake complete between nylon (hook-driven junk) and the reference")

	// Data plane, both directions.
	ping := tuntest.Ping(refAddr, nylonAddr)
	nylonTun.Outbound <- ping
	expectPacket(t, refTun.Inbound, ping, "nylon->reference")
	pong := tuntest.Ping(nylonAddr, refAddr)
	refTun.Outbound <- pong
	expectPacket(t, nylonTun.Inbound, pong, "reference->nylon")

	// The junk switch — the per-strategy junk of a rotation landing the
	// connection on a different strategy. The session must survive (no
	// re-handshake, data keeps flowing): junk decorates initiations, not
	// keypairs.
	firstHandshake := handshakeSecs(t, refDev, "awgref")
	src.set(device.JunkSpec{
		Jc:   1,
		Jmin: 64,
		Jmax: 65,
		I:    [5]string{"", "<t>", "", "", ""},
	})

	ping2 := tuntest.Ping(refAddr, nylonAddr)
	nylonTun.Outbound <- ping2
	expectPacket(t, refTun.Inbound, ping2, "nylon->reference (after the junk switch)")

	// No re-handshake: the reference's peer session is the original one.
	if second := handshakeSecs(t, refDev, "awgref"); second != firstHandshake {
		t.Fatalf("the junk switch forced a re-handshake (session did not survive): %d -> %d", firstHandshake, second)
	}
	t.Log("junk switched with the session intact — per-strategy junk is wire-equivalent to device-driven junk")
}
