//go:build integration

package integration

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"runtime/pprof"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/encodeous/nylon/core"
	"github.com/encodeous/nylon/internal/logging"
	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/conn/bindtest"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/polyamide/tun"
	"github.com/encodeous/nylon/polyamide/tun/tuntest"
	"github.com/encodeous/nylon/state"
)

type Signal chan bool

func NewSignal() Signal {
	return make(chan bool)
}
func (s Signal) Trigger() {
	select {
	case <-s:
	default:
		close(s)
	}
}
func (s Signal) Triggered() bool {
	select {
	case <-s:
		return true
	default:
		return false
	}
}
func (s Signal) Wait() {
	<-s
}

type VirtualLink struct {
	Edge    state.Pair[bindtest.ChannelEndpoint2, bindtest.ChannelEndpoint2]
	Latency time.Duration
	Jitter  time.Duration

	packetLoss atomic.Uint64

	// Port-hopping (range) links: instead of an exact Edge.V2 match, any
	// destination addr:port with port in DstPorts is delivered to DstNode.
	dstNode  state.NodeId
	dstAddr  netip.Addr
	dstPorts conn.PortRange
	// Reverse range links: any source port from srcAddrMatch to Edge.V2.
	srcAddrMatch netip.Addr

	// TSPU emulation: when > 0, at most FlowBudget packets are delivered per
	// (source, destination) flow before the flow is dropped for the rest of
	// the link's life. Applies to the Edge.V1 -> Edge.V2 direction (the
	// reverse direction of a range link is a separate exact link).
	flowBudget int
	flowMu     sync.Mutex
	flowCounts map[flowKey]int

	// distinct destination ports seen on this link (range links only); used
	// by tests to assert that port rotation actually happened
	portsMu   sync.Mutex
	portsSeen map[uint16]struct{}

	// per-port activity timeline: first/last time a destination port carried
	// a packet on a range link (forward direction), and first/last time a
	// source port carried a packet on a reverse (srcAddrMatch) link. The
	// ground truth for "retired ports must go quiet" assertions: a port whose
	// carrying window ended but whose lastSeen keeps advancing is a zombie
	// (still passing traffic long after rotation away).
	firstSeenFwd map[uint16]time.Time
	lastSeenFwd  map[uint16]time.Time
	firstSeenRev map[uint16]time.Time
	lastSeenRev  map[uint16]time.Time
}

// PortTimeline describes a port's carrying activity window on a link.
type PortTimeline struct {
	First time.Time
	Last  time.Time
}

// ForwardTimeline returns the first/last packet times of every destination
// port that carried packets on a range link (client -> server direction).
func (v *VirtualLink) ForwardTimeline() map[uint16]PortTimeline {
	v.portsMu.Lock()
	defer v.portsMu.Unlock()
	out := make(map[uint16]PortTimeline, len(v.lastSeenFwd))
	for p, last := range v.lastSeenFwd {
		out[p] = PortTimeline{First: v.firstSeenFwd[p], Last: last}
	}
	return out
}

// ReverseTimeline returns the first/last packet times of every source port
// that carried packets on a reverse link (server -> client direction).
func (v *VirtualLink) ReverseTimeline() map[uint16]PortTimeline {
	v.portsMu.Lock()
	defer v.portsMu.Unlock()
	out := make(map[uint16]PortTimeline, len(v.lastSeenRev))
	for p, last := range v.lastSeenRev {
		out[p] = PortTimeline{First: v.firstSeenRev[p], Last: last}
	}
	return out
}

type flowKey struct {
	src netip.AddrPort
	dst netip.AddrPort
}

// IsRangeLink reports whether this link matches a destination port range.
func (v *VirtualLink) IsRangeLink() bool {
	return v.dstPorts.Valid()
}

// Matches reports whether a packet from -> to is routable over this link.
func (v *VirtualLink) Matches(from, to bindtest.ChannelEndpoint2) bool {
	if v.IsRangeLink() {
		return bindtest.ChannelEndpoint2(v.Edge.V1) == from &&
			netip.AddrPort(to).Addr() == v.dstAddr &&
			v.dstPorts.Contains(netip.AddrPort(to).Port())
	}
	if v.srcAddrMatch.IsValid() {
		return netip.AddrPort(from).Addr() == v.srcAddrMatch && v.Edge.V2 == to
	}
	return v.Edge.V1 == from && v.Edge.V2 == to
}

// WithFlowBudget arms the per-flow packet budget (TSPU volume-ban emulation).
func (v *VirtualLink) WithFlowBudget(n int) *VirtualLink {
	v.flowBudget = n
	return v
}

func (v *VirtualLink) flowAllows(from, to bindtest.ChannelEndpoint2) bool {
	if v.flowBudget <= 0 {
		return true
	}
	v.flowMu.Lock()
	defer v.flowMu.Unlock()
	if v.flowCounts == nil {
		v.flowCounts = make(map[flowKey]int)
	}
	k := flowKey{src: netip.AddrPort(from), dst: netip.AddrPort(to)}
	v.flowCounts[k]++
	return v.flowCounts[k] <= v.flowBudget
}

// DistinctDstPorts reports how many distinct destination ports have carried
// packets over this link (range links only).
func (v *VirtualLink) DistinctDstPorts() int {
	v.portsMu.Lock()
	defer v.portsMu.Unlock()
	return len(v.portsSeen)
}

// CarriedPorts returns the distinct destination ports that have carried
// packets over this link (range links only) — the ground truth of "this port
// was actually used" for ghost-link assertions, independent of when the
// test's sampling loop happens to run.
func (v *VirtualLink) CarriedPorts() []uint16 {
	v.portsMu.Lock()
	defer v.portsMu.Unlock()
	out := make([]uint16, 0, len(v.portsSeen))
	for p := range v.portsSeen {
		out = append(out, p)
	}
	return out
}

// observePort records a destination port on a range link.
func (v *VirtualLink) observePort(port uint16) {
	now := time.Now()
	v.portsMu.Lock()
	if v.portsSeen == nil {
		v.portsSeen = make(map[uint16]struct{})
	}
	v.portsSeen[port] = struct{}{}
	if v.lastSeenFwd == nil {
		v.firstSeenFwd = make(map[uint16]time.Time)
		v.lastSeenFwd = make(map[uint16]time.Time)
	}
	if _, ok := v.firstSeenFwd[port]; !ok {
		v.firstSeenFwd[port] = now
	}
	v.lastSeenFwd[port] = now
	v.portsMu.Unlock()
}

// observeRevPort records a reply source port on a reverse (srcAddrMatch) link.
func (v *VirtualLink) observeRevPort(port uint16) {
	now := time.Now()
	v.portsMu.Lock()
	if v.lastSeenRev == nil {
		v.firstSeenRev = make(map[uint16]time.Time)
		v.lastSeenRev = make(map[uint16]time.Time)
	}
	if _, ok := v.firstSeenRev[port]; !ok {
		v.firstSeenRev[port] = now
	}
	v.lastSeenRev[port] = now
	v.portsMu.Unlock()
}

func (v *VirtualLink) simulate(pkt []byte, len int, from, to bindtest.ChannelEndpoint2, i *InMemoryNetwork) {
	//fmt.Printf("begin send: %s -> %s\n", from.DstToString(), to.DstToString())
	if rand.Float64() < v.loss() {
		//fmt.Printf("dropped send: %s -> %s\n", from.DstToString(), to.DstToString())
		return
	}

	var toIdx int
	// deliverEp is the endpoint the receiver attributes the packet to. For
	// range links it carries the arrival port as a hint: the receiver's
	// device roams onto the hinted endpoint and its replies (and nylon
	// probe traffic routed through it) return through the same port —
	// exactly how the real MultiBind answers from the receiving socket.
	// Without the hint every reply would be synthesized from the last
	// flow, which hides stale-pin behaviours (see the retired-port
	// tests).
	var deliverEp conn.Endpoint = from
	if v.IsRangeLink() {
		toIdx = i.cfg.IndexOf(v.dstNode)
		// record the reply source for the flow so the destination node's
		// replies carry the same server-side port the client targeted (this
		// mirrors a real range listener answering from the receiving port)
		i.setFlowSrc(v.dstNode, from, to)
		v.observePort(netip.AddrPort(to).Port())
		deliverEp = bindtest.NewHintedEndpoint(from, netip.AddrPort(to).Port())
	} else if v.srcAddrMatch.IsValid() {
		v.observeRevPort(netip.AddrPort(from).Port())
		toIdx = i.cfg.IndexOf(i.cfg.Endpoints[to.DstToString()])
	} else {
		toIdx = i.cfg.IndexOf(i.cfg.Endpoints[to.DstToString()])
	}
	// TSPU emulation: enforce the per-flow budget
	if !v.flowAllows(from, to) {
		return
	}
	if v.Latency != 0 {
		simJitter := rand.Float64() * float64(v.Jitter.Nanoseconds())
		simLat := v.Latency + time.Duration(simJitter)
		go func() { // this is quite costly, but should be fine as long as we don't send packets too fast
			select {
			case <-i.cfg.Context.Done():
				return
			case <-time.After(simLat):
				//fmt.Printf("delay sent: %s -> %s\n", from.DstToString(), to.DstToString())
				err := i.binds[toIdx].Send([][]byte{pkt[:len]}, deliverEp)
				if err != nil && !errors.Is(err, net.ErrClosed) {
					panic(err)
				}
			}
		}()
	} else {
		//fmt.Printf("sent: %s -> %s\n", from.DstToString(), to.DstToString())
		err := i.binds[toIdx].Send([][]byte{pkt[:len]}, deliverEp)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			panic(err)
		}
	}
}

func (v *VirtualLink) WithLatency(lat, jitter time.Duration) *VirtualLink {
	v.Latency = lat
	v.Jitter = jitter
	return v
}

func (v *VirtualLink) loss() float64 {
	return math.Float64frombits(v.packetLoss.Load())
}

func (v *VirtualLink) WithPacketLoss(loss float64) *VirtualLink {
	v.SetPacketLoss(loss)
	return v
}

func (v *VirtualLink) SetPacketLoss(loss float64) {
	v.packetLoss.Store(math.Float64bits(loss))
}

type VirtualHarness struct {
	Central          state.CentralCfg
	Context          context.Context
	Cancel           context.CancelCauseFunc
	Local            []state.LocalCfg
	Net              *InMemoryNetwork
	Nylons           []atomic.Pointer[core.Nylon]
	Links            []*VirtualLink
	linksMu          sync.RWMutex
	Endpoints        map[string]state.NodeId
	UntrackedRouting bool
	LogLevel         *slog.Level
	Tunables         *state.RouterTunables
}

func (v *VirtualHarness) IndexOf(id state.NodeId) int {
	return slices.IndexFunc(v.Central.Routers, func(cfg state.RouterCfg) bool {
		return cfg.Id == id
	})
}

func (v *VirtualHarness) NewNode(id state.NodeId, virtPrefix string) {
	privKey := state.GenerateKey()
	locCfg := state.LocalCfg{
		Key:              privKey,
		Id:               id,
		Port:             25565,
		NoNetConfigure:   true,
		UseSystemRouting: !v.UntrackedRouting,
	}
	ncfg := state.RouterCfg{
		NodeCfg: state.NodeCfg{
			Id:     id,
			PubKey: privKey.Pubkey(),
			Prefixes: []state.PrefixHealthWrapper{
				{
					&state.StaticPrefixHealth{
						Prefix: netip.MustParsePrefix(virtPrefix),
						Metric: 0,
					},
				},
			},
		},
	}
	v.Central.Routers = append(v.Central.Routers, ncfg)
	v.Local = append(v.Local, locCfg)
}

func (v *VirtualHarness) AddLink(from, to string) *VirtualLink {
	link := &VirtualLink{}
	link.Edge = state.Pair[bindtest.ChannelEndpoint2, bindtest.ChannelEndpoint2]{
		V1: bindtest.ChannelEndpoint2(netip.MustParseAddrPort(from)),
		V2: bindtest.ChannelEndpoint2(netip.MustParseAddrPort(to)),
	}
	v.linksMu.Lock()
	v.Links = append(v.Links, link)
	v.linksMu.Unlock()
	return link
}

// AddLinkRange adds a port-hopping link: packets from `from` (an exact
// addr:port) to dstAddr:any-port-in-ports are delivered to dstNode. The
// reverse direction must be added separately (usually an exact AddLink).
func (v *VirtualHarness) AddLinkRange(from, dstNode, dstAddr string, ports conn.PortRange) *VirtualLink {
	link := &VirtualLink{
		dstNode:  state.NodeId(dstNode),
		dstAddr:  netip.MustParseAddr(dstAddr),
		dstPorts: ports,
	}
	link.Edge = state.Pair[bindtest.ChannelEndpoint2, bindtest.ChannelEndpoint2]{
		V1: bindtest.ChannelEndpoint2(netip.MustParseAddrPort(from)),
	}
	v.linksMu.Lock()
	v.Links = append(v.Links, link)
	v.linksMu.Unlock()
	return link
}

// AddLinkFromAddr adds a reverse port-hopping link: packets from any source
// port of fromAddr to the exact `to` endpoint are delivered to the node that
// owns `to` (the normal exact endpoint mapping). Used for the server -> client
// direction, where the reply source port follows the flow.
func (v *VirtualHarness) AddLinkFromAddr(fromAddr, to string) *VirtualLink {
	link := &VirtualLink{
		srcAddrMatch: netip.MustParseAddr(fromAddr),
	}
	link.Edge = state.Pair[bindtest.ChannelEndpoint2, bindtest.ChannelEndpoint2]{
		V2: bindtest.ChannelEndpoint2(netip.MustParseAddrPort(to)),
	}
	v.linksMu.Lock()
	v.Links = append(v.Links, link)
	v.linksMu.Unlock()
	return link
}

func (v *VirtualHarness) Start() chan error {
	ctx, cancel := context.WithCancelCause(context.Background())
	v.Context = ctx
	v.Cancel = cancel
	v.Nylons = make([]atomic.Pointer[core.Nylon], len(v.Central.Routers))
	errChan := make(chan error, 128) // a large number so we dont get blocked
	vn := &InMemoryNetwork{}
	v.Net = vn
	vn.cfg = v
	nodes := len(v.Central.Routers)
	vn.virtTun = make([]*tuntest.ChannelTUN, nodes)
	vn.binds = make([]conn.Bind, nodes)
	vn.readyCond = sync.NewCond(&sync.Mutex{})
	// pick the first endpoint specified for each node
	vn.EpOutMapping = func(curNode state.NodeId, to bindtest.ChannelEndpoint2) bindtest.ChannelEndpoint2 {
		// port-hopping flow tracking: when this node has received traffic on a
		// range link, its replies to that source must carry the server-side
		// port the flow targeted (mirrors a range listener replying from the
		// receiving port)
		if src, ok := vn.flowSrc(curNode, to); ok {
			return src
		}
		for k, x := range v.Endpoints {
			if x == curNode {
				return bindtest.ChannelEndpoint2(netip.MustParseAddrPort(k))
			}
		}
		panic(fmt.Sprintf("no endpoint found for node %v", curNode))
	}
	for e, n := range v.Endpoints {
		idx := v.IndexOf(n)
		v.Central.Routers[idx].Endpoints = append(v.Central.Routers[idx].Endpoints, e)
	}
	if v.LogLevel == nil {
		v.LogLevel = new(slog.LevelDebug)
	}
	for idx, rt := range v.Central.Routers {
		logger, _, err := logging.New(logging.Config{
			Component: "nylon",
			Node:      string(rt.Id),
			Level:     *v.LogLevel,
		})
		if err != nil {
			errChan <- err
			return errChan
		}
		n, err := core.NewNylon(v.Central, v.Local[idx], logger, "", map[string]any{
			"vnet": vn,
		}, state.NylonOptions{DBG_log_wireguard: true}, v.Tunables)
		if err != nil {
			errChan <- err
			return errChan
		}
		v.Nylons[idx].Store(n)
	}
	v.Net.Ready()

	startDelay := time.Duration(0)
	for idx, rt := range v.Central.Routers {
		sd := startDelay
		n := v.Nylons[idx].Load()
		go func() {
			timer := time.NewTimer(sd)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}
			labels := pprof.Labels("nylon node", string(rt.Id))
			pprof.Do(context.Background(), labels, func(_ context.Context) {
				if err := n.Start(); err != nil {
					errChan <- err
				}
			})
		}()
		startDelay += 500 * time.Millisecond
	}
	return errChan
}

func (v *VirtualHarness) Stop() {
	println("Stopping VirtualHarness")
	v.Cancel(fmt.Errorf("stopping harness"))
	for idx, _ := range v.Central.Routers {
		v.Nylons[idx].Load().Stop()
	}
	v.Net.Stop()
	println("Stopped VirtualHarness")
}

type PacketFilter func(node state.NodeId, src, dst netip.Addr, data []byte) bool // return true to intercept, and stop the rest of the stack
func (h PacketFilter) TryApply(node state.NodeId, src, dst netip.Addr, data []byte) bool {
	if h == nil {
		return false
	}
	return h(node, src, dst, data)
}

type OutMapping func(curNode state.NodeId, to bindtest.ChannelEndpoint2) bindtest.ChannelEndpoint2

type InMemoryNetwork struct {
	sync.Mutex
	cfg            *VirtualHarness
	binds          []conn.Bind
	virtTun        []*tuntest.ChannelTUN
	SelfHandler    PacketFilter // packet filter for handling packets destined for the current node
	TransitHandler PacketFilter // packet filter for handling packets passing through the current node
	EpOutMapping   OutMapping
	ready          atomic.Bool
	readyCond      *sync.Cond

	flowMu   sync.Mutex
	flowSrcs map[flowKey]bindtest.ChannelEndpoint2 // (node, dst) -> synthesized reply source
}

// setFlowSrc records that replies from node `n` to `dst` should be sourced
// from `src` (used by range links to mirror port-preserving replies).
func (i *InMemoryNetwork) setFlowSrc(n state.NodeId, dst, src bindtest.ChannelEndpoint2) {
	i.flowMu.Lock()
	defer i.flowMu.Unlock()
	if i.flowSrcs == nil {
		i.flowSrcs = make(map[flowKey]bindtest.ChannelEndpoint2)
	}
	i.flowSrcs[flowKeyFor(n, dst)] = src
}

func (i *InMemoryNetwork) flowSrc(n state.NodeId, dst bindtest.ChannelEndpoint2) (bindtest.ChannelEndpoint2, bool) {
	i.flowMu.Lock()
	defer i.flowMu.Unlock()
	src, ok := i.flowSrcs[flowKeyFor(n, dst)]
	return src, ok
}

func flowKeyFor(n state.NodeId, dst bindtest.ChannelEndpoint2) flowKey {
	return flowKey{src: netip.MustParseAddrPort("0.0.0.0:" + strconv.Itoa(int(numericNodeId(n)))), dst: netip.AddrPort(dst)}
}

func numericNodeId(n state.NodeId) uint16 {
	// node ids are arbitrary strings; use a stable numeric hash for the
	// synthetic flow-source key. Collisions are impossible in practice for
	// test-sized meshes because the key also carries the dst.
	h := fnv.New32a()
	_, _ = h.Write([]byte(n))
	return uint16(h.Sum32())
}

func (i *InMemoryNetwork) WaitForReady() {
	i.readyCond.L.Lock()
	defer i.readyCond.L.Unlock()
	for !i.ready.Load() {
		i.readyCond.Wait()
	}
}

func (i *InMemoryNetwork) Ready() {
	i.Lock()
	defer i.Unlock()
	i.ready.Store(true)
	i.readyCond.Broadcast()
}

func (i *InMemoryNetwork) virtualRouteTable(node state.NodeId, src, dst netip.Addr, data []byte, pkt []byte) bool {
	curCfg := i.cfg.Central.GetNode(node)
	if pkt[8] == 0 { // handle self if ttl is 0 as well
		if i.SelfHandler.TryApply(node, src, dst, data) {
			return true
		}
	}
	for _, prefix := range curCfg.Prefixes {
		if prefix.GetPrefix().Contains(dst) {
			if i.SelfHandler.TryApply(node, src, dst, data) {
				return true
			}
		}
	}
	curIdx := i.cfg.IndexOf(node)

	if !i.TransitHandler.TryApply(node, src, dst, data) {
		// default routing behaviour
		for _, n := range i.cfg.Central.Routers {
			if node == n.Id {
				continue
			}
			for _, prefix := range n.Prefixes {
				if prefix.GetPrefix().Contains(dst) {
					// route to this node
					select {
					case i.virtTun[curIdx].Outbound <- pkt: // send back into our tun to get routed by WireGuard/Polyamide
						return true
					default:
						fmt.Printf("%s's tun is not ready to accept data\n", n.Id)
						return true
					}
				}
			}
		}
		return false
	}
	return true
}

func (i *InMemoryNetwork) virtualInternet(pkt []byte, len int, from, to bindtest.ChannelEndpoint2) {
	// simulate network conditions
	i.cfg.linksMu.RLock()
	idx := slices.IndexFunc(i.cfg.Links, func(link *VirtualLink) bool {
		return link.Matches(from, to)
	})
	var link *VirtualLink
	if idx != -1 {
		link = i.cfg.Links[idx]
	}
	i.cfg.linksMu.RUnlock()
	if link == nil {
		return // no connection, dropped packet
	}
	link.simulate(pkt, len, from, to, i)
}

func (i *InMemoryNetwork) Bind(node state.NodeId) conn.Bind {
	i.Lock()
	defer i.Unlock()
	epSendMapping := func(to bindtest.ChannelEndpoint2) bindtest.ChannelEndpoint2 {
		return i.EpOutMapping(node, to)
	}
	bp := bindtest.NewChannelBind2()

	remote := bp[0] // simulate an actual port opening
	open, _, err := remote.Open(0)
	if err != nil {
		return nil
	}
	numId := i.cfg.IndexOf(node)
	i.binds[numId] = remote
	go func() {
		// bind listener routine for packets sent from this node
		bufSize := remote.BatchSize()
		pktBuf := make([][]byte, bufSize)
		pktBuf[0] = make([]byte, device.MaxMessageSize)
		lenBuf := make([]int, bufSize)
		epBuf := make([]conn.Endpoint, bufSize)
		i.WaitForReady()
		for {
			for _, recv := range open {
				n, err := recv(pktBuf, lenBuf, epBuf)
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						panic(err)
					}
					return
				}
				for pi := range n {
					if lenBuf[pi] == 0 {
						continue
					}
					toIp, srcHint := bindtest.EndpointDstOf(epBuf[pi])
					fromIp := epSendMapping(toIp)
					if srcHint != 0 {
						// port-hopping reply symmetry: this packet rides a
						// hinted (range-listener) flow — the reply must originate
						// from the hinted port, not whatever flow happened to
						// arrive last
						if ap := netip.AddrPort(fromIp); ap.Port() != srcHint {
							fromIp = bindtest.ChannelEndpoint2(netip.AddrPortFrom(ap.Addr(), srcHint))
						}
					}
					i.virtualInternet(slices.Clone(pktBuf[pi]), lenBuf[pi], fromIp, toIp)
				}
			}
		}
	}()
	// The device side is returned as-is: in the port-as-endpoint design the
	// hop accounting lives in the device peer send path (peer.SetHop), wired
	// from the nylon core, and works on any bind — including this channel bind.
	return bp[1]
}

func (i *InMemoryNetwork) Tun(node state.NodeId) tun.Device {
	i.Lock()
	defer i.Unlock()
	const (
		ipv4Size = 20
	)
	bt := tuntest.NewChannelTUN()

	numId := slices.IndexFunc(i.cfg.Central.Routers, func(cfg state.RouterCfg) bool {
		return cfg.Id == node
	})

	i.virtTun[numId] = bt
	go func() {
		i.WaitForReady()
		for {
			select {
			case <-i.cfg.Context.Done():
				return
			case pkt := <-bt.Inbound:
				// wireguard doesn't actually verify checksum for ip
				ip := pkt[0:ipv4Size]
				if pkt[0]>>4 != 4 {
					panic("unexpected packet, not ipv4")
				}
				var src, dst netip.Addr
				err := src.UnmarshalBinary(ip[12:16])
				if err != nil {
					panic(err)
				}
				err = dst.UnmarshalBinary(ip[16:20])
				if err != nil {
					panic(err)
				}
				if !i.virtualRouteTable(node, src, dst, pkt[ipv4Size:], pkt) {
					panic(fmt.Sprintf("unhandled packet src: %v, dst: %v", src, dst))
				}
			}
		}
	}()
	return bt.TUN()
}

func (i *InMemoryNetwork) Send(node state.NodeId, src, dst string, pkt []byte, ttl byte) {
	const (
		ipv4Size = 20
	)
	numId := i.cfg.IndexOf(node)
	ipPkt := append(make([]byte, ipv4Size), pkt...)
	ip := ipPkt[0:ipv4Size]
	ip[0] = 4 << 4
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipv4Size+len(pkt)))
	ip[8] = ttl
	copy(ipPkt[12:16], netip.MustParseAddr(src).AsSlice())
	copy(ipPkt[16:20], netip.MustParseAddr(dst).AsSlice())
	i.virtTun[numId].Outbound <- ipPkt
}

func (i *InMemoryNetwork) Stop() {
	for _, d := range i.binds {
		if d != nil {
			err := d.Close()
			if err != nil {
				panic(err)
			}
		}
	}
}
