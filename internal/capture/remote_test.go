package capture

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/bpf"

	"github.com/andreacoppini/packhound/internal/pkt"
)

func mirrored() []byte {
	return pkt.Frame(pkt.Spec{Src: netip.MustParseAddr("10.7.0.15"), Dst: netip.MustParseAddr("239.3.1.1"),
		SrcPort: 5000, DstPort: 5701, Payload: bytes.Repeat([]byte{0x47}, 188)})
}

// expectFrame reads frames from r until the mirrored one arrives.
func expectFrame(t *testing.T, r *Remote, want []byte) {
	t.Helper()
	got := make(chan []byte, 1)
	go func() {
		f, err := r.Next()
		if err == nil {
			got <- append([]byte(nil), f.Data...)
		}
	}()
	select {
	case f := <-got:
		if !bytes.Equal(f, want) {
			t.Errorf("got %d bytes, want %d", len(f), len(want))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no mirrored frame arrived")
	}
}

func TestRemoteTZSP(t *testing.T) {
	r, err := OpenRemote(RemoteConfig{Proto: RemoteTZSP, Listen: netip.MustParseAddr("127.0.0.1"), Session: -1})
	if err != nil {
		t.Skip("port 37008 unavailable:", err)
	}
	defer r.Close()
	c, err := net.Dial("udp4", "127.0.0.1:37008")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	inner := mirrored()
	c.Write(append([]byte{1, 0, 0, 1, 1}, inner...))
	expectFrame(t, r, inner)
	if st := r.Stats(); st.Frames != 1 || st.From != "127.0.0.1" {
		t.Errorf("stats %+v", st)
	}
}

// TestRemoteERSPAN sends ERSPAN Type II from session 7 and then 9, and
// keeps only session 9. It needs a raw socket, so root.
func TestRemoteERSPAN(t *testing.T) {
	r, err := OpenRemote(RemoteConfig{Proto: RemoteERSPAN, Listen: netip.MustParseAddr("127.0.0.1"), Session: 9})
	if err != nil {
		t.Skip("raw sockets unavailable:", err)
	}
	defer r.Close()
	c, err := net.Dial("ip4:gre", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	inner := mirrored()
	for _, session := range []byte{7, 9} {
		b := binary.BigEndian.AppendUint16(nil, 0x1000)
		b = binary.BigEndian.AppendUint16(b, 0x88be)
		b = append(b, 0, 0, 0, 1)                            // sequence number
		b = append(b, 0x10, 0x00, 0x00, session, 0, 0, 0, 0) // ERSPAN II
		b = append(b, inner...)
		inner[len(inner)-1] = session // tell the two frames apart
		c.Write(append(b[:len(b)-1], session))
	}
	expectFrame(t, r, inner)
	if st := r.Stats(); st.Frames != 1 || st.Ignored != 1 || st.Session != 9 {
		t.Errorf("stats %+v", st)
	}
}

// TestGREFilter runs the kernel filter for ERSPAN over frames: GRE passes,
// untagged or tagged; everything else does not.
func TestGREFilter(t *testing.T) {
	vm, err := bpf.NewVM(rawToInstructions(t, greOnly))
	if err != nil {
		t.Fatal(err)
	}
	ipv4 := func(proto byte) []byte {
		return []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, proto, 0, 0, 192, 0, 2, 9, 192, 0, 2, 10}
	}
	eth := func(et uint16, rest []byte) []byte {
		b := append([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, byte(et>>8), byte(et))
		return append(b, append(rest, make([]byte, 20)...)...)
	}
	cases := map[string]struct {
		frame []byte
		pass  bool
	}{
		"GRE":        {eth(0x0800, ipv4(47)), true},
		"tagged GRE": {eth(0x8100, append([]byte{0x02, 0xbc, 0x08, 0x00}, ipv4(47)...)), true},
		"UDP":        {eth(0x0800, ipv4(17)), false},
		"tagged UDP": {eth(0x8100, append([]byte{0x02, 0xbc, 0x08, 0x00}, ipv4(17)...)), false},
		"IPv6":       {eth(0x86dd, make([]byte, 40)), false},
		"ARP":        {eth(0x0806, make([]byte, 28)), false},
	}
	for name, c := range cases {
		n, err := vm.Run(c.frame)
		if err != nil || (n > 0) != c.pass {
			t.Errorf("%s: returned %d, %v; want pass %v", name, n, err, c.pass)
		}
	}
}

func rawToInstructions(t *testing.T, raw []bpf.RawInstruction) []bpf.Instruction {
	ins, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("filter does not disassemble")
	}
	return ins
}

// TestERSPANCapture receives ERSPAN through the capture device, the way
// Packhound does without a raw socket: on loopback here, which needs root.
func TestERSPANCapture(t *testing.T) {
	lo, err := FindInterface("lo")
	if err != nil {
		t.Skip("no lo:", err)
	}
	r, err := openERSPANCapture(RemoteConfig{Proto: RemoteERSPAN, Listen: netip.MustParseAddr("127.0.0.1"), Session: 9, Interface: lo})
	if err != nil {
		t.Skip("capture unavailable:", err)
	}
	defer r.Close()
	c, err := net.Dial("ip4:gre", "127.0.0.1")
	if err != nil {
		t.Skip("raw sockets unavailable:", err)
	}
	defer c.Close()
	inner := mirrored()
	for _, session := range []byte{7, 9} {
		b := []byte{0x10, 0x00, 0x88, 0xbe, 0, 0, 0, 1, 0x10, 0x00, 0x00, session, 0, 0, 0, 0}
		f := append([]byte(nil), inner...)
		f[len(f)-1] = session
		c.Write(append(b, f...))
	}
	inner[len(inner)-1] = 9
	expectFrame(t, r, inner)
	st := r.Stats()
	if st.Frames != 1 || st.Ignored != 1 || st.From != "127.0.0.1" || st.Via != "the capture device on lo" {
		t.Errorf("stats %+v", st)
	}
}
