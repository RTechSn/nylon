package device

import (
	"net/netip"
	"strconv"
	"testing"

	"github.com/encodeous/nylon/polyamide/conn"
)

func ep4(port uint16) conn.Endpoint {
	return &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("192.0.2.1:" + strconv.Itoa(int(port)))}
}

func TestPartitionBuffersByEndpointAndTOS(t *testing.T) {
	peer := &Peer{} // bare peer: no hop source, no learned endpoints; eps carry no nils
	e1, e2 := ep4(1), ep4(2)

	bufs := [][]byte{{1}, {2}, {3}, {4}, {5}}
	eps := []conn.Endpoint{e1, e2, e1, e1, e2}
	tos := []byte{0, 0, 0, 0xb8, 0xb8}

	var outBufs [][]byte
	var outEps []conn.Endpoint
	var outTos []byte
	if err := partitionBuffersByEndpoint(bufs, eps, tos, &outBufs, &outEps, &outTos, peer); err != nil {
		t.Fatal(err)
	}

	// (endpoint, TOS) groups, within-group order stable:
	//   (e1, 0)   -> bufs 0, 2
	//   (e2, 0)   -> buf 1
	//   (e1, b8)  -> buf 3
	//   (e2, b8)  -> buf 4
	wantEps := []conn.Endpoint{e1, e1, e2, e1, e2}
	wantTos := []byte{0, 0, 0, 0xb8, 0xb8}
	if len(outBufs) != 5 || len(outEps) != 5 || len(outTos) != 5 {
		t.Fatalf("partition lengths: %d/%d/%d", len(outBufs), len(outEps), len(outTos))
	}
	for i, b := range [][]byte{{1}, {3}, {2}, {4}, {5}} {
		if outBufs[i][0] != b[0] {
			t.Errorf("outBufs[%d] = %d, want %d", i, outBufs[i][0], b[0])
		}
		if outEps[i] != wantEps[i] {
			t.Errorf("outEps[%d] = %v, want group %d", i, outEps[i], i)
		}
		if outTos[i] != wantTos[i] {
			t.Errorf("outTos[%d] = %#02x, want %#02x", i, outTos[i], wantTos[i])
		}
	}
}

func TestPartitionBuffersNilTOSGroupsByEndpointOnly(t *testing.T) {
	peer := &Peer{}
	e1, e2 := ep4(1), ep4(2)

	bufs := [][]byte{{1}, {2}, {3}, {4}, {5}}
	eps := []conn.Endpoint{e1, e2, e1, e1, e2}

	var outBufs [][]byte
	var outEps []conn.Endpoint
	var outTos []byte
	if err := partitionBuffersByEndpoint(bufs, eps, nil, &outBufs, &outEps, &outTos, peer); err != nil {
		t.Fatal(err)
	}

	// all-unmarked: pure endpoint grouping, order stable within a group
	wantEps := []conn.Endpoint{e1, e1, e1, e2, e2}
	for i, b := range [][]byte{{1}, {3}, {4}, {2}, {5}} {
		if outBufs[i][0] != b[0] {
			t.Errorf("outBufs[%d] = %d, want %d", i, outBufs[i][0], b[0])
		}
		if outEps[i] != wantEps[i] {
			t.Errorf("outEps[%d] mismatch at %d", i, i)
		}
		if outTos[i] != 0 {
			t.Errorf("outTos[%d] = %#02x, want 0", i, outTos[i])
		}
	}
}
