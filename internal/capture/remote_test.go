package capture

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

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
