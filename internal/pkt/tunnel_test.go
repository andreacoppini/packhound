package pkt

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// innerFrame is a mirrored multicast datagram, tagged VLAN 700 as a trunk
// port would carry it.
func innerFrame() []byte {
	f := Frame(Spec{Src: netip.MustParseAddr("10.7.0.15"), Dst: netip.MustParseAddr("239.3.1.1"),
		Proto: ProtoUDP, SrcPort: 5000, DstPort: 5701, Payload: bytes.Repeat([]byte{0x47}, 188)})
	tagged := append(append([]byte(nil), f[:12]...), 0x81, 0x00, 0x02, 0xbc) // VLAN 700
	return append(tagged, f[12:]...)
}

func greHeader(flags, proto uint16, extra int) []byte {
	b := binary.BigEndian.AppendUint16(nil, flags)
	b = binary.BigEndian.AppendUint16(b, proto)
	return append(b, make([]byte, extra)...)
}

// TestGRE peels every encapsulation a switch sends mirrored traffic in,
// and the frame inside decodes as the multicast datagram it was.
func TestGRE(t *testing.T) {
	inner := innerFrame()
	erspan2 := []byte{0x10, 0x00, 0x01, 0x2a, 0, 0, 0, 0}                   // version 1, session 0x12a
	erspan3 := []byte{0x20, 0x00, 0x00, 0x07, 1, 2, 3, 4, 0, 0, 0x00, 0x00} // version 2, session 7, Ethernet
	erspan3o := append(append([]byte(nil), erspan3...), make([]byte, 8)...)
	erspan3o[11] |= 1 // a platform subheader follows
	cases := []struct {
		name    string
		pkt     []byte
		session int
	}{
		{"type I", append(greHeader(0x0000, 0x88be, 0), inner...), -1},
		{"type II", append(append(greHeader(0x1000, 0x88be, 4), erspan2...), inner...), 0x12a},
		{"type III", append(append(greHeader(0x1000, 0x22eb, 4), erspan3...), inner...), 7},
		{"type III with subheader", append(append(greHeader(0x1000, 0x22eb, 4), erspan3o...), inner...), 7},
		{"bridging with key and checksum", append(greHeader(0xa000, 0x6558, 8), inner...), -1},
	}
	for _, c := range cases {
		frame, session, ok := GRE(c.pkt)
		if !ok || session != c.session || !bytes.Equal(frame, inner) {
			t.Errorf("%s: ok %v, session %d, frame %d bytes (want %d)", c.name, ok, session, len(frame), len(inner))
			continue
		}
		var p Packet
		if !Decode(LinkEthernet, frame, time.Time{}, &p) || p.Dst.String() != "239.3.1.1" || p.DstPort != 5701 || p.VLAN != 700 {
			t.Errorf("%s: inner frame decoded as %+v", c.name, p)
		}
	}
	for name, b := range map[string][]byte{
		"GRE version 1":       append(greHeader(0x0001, 0x88be, 0), inner...),
		"other protocol":      append(greHeader(0x0000, 0x0800, 0), inner...),
		"type III, IP frames": append(append(greHeader(0x1000, 0x22eb, 4), 0x20, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0x04, 0), inner...),
		"cut short":           greHeader(0x1000, 0x88be, 2),
	} {
		if _, _, ok := GRE(b); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTZSP(t *testing.T) {
	inner := innerFrame()
	// Version 1, received, Ethernet; a padding byte, a 2-byte field, end.
	b := append([]byte{1, 0, 0, 1, 0, 0x0a, 2, 0xaa, 0xbb, 1}, inner...)
	frame, ok := TZSP(b)
	if !ok || !bytes.Equal(frame, inner) {
		t.Fatalf("ok %v, %d bytes", ok, len(frame))
	}
	if _, ok := TZSP(append([]byte{1, 0, 0, 0x12, 1}, inner...)); ok {
		t.Error("accepted an 802.11 encapsulation")
	}
}

func TestIPv4Header(t *testing.T) {
	h := []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, ProtoGRE, 0, 0, 192, 0, 2, 9, 10, 0, 0, 1, 0xaa}
	proto, src, rest, ok := IPv4Header(h)
	if !ok || proto != ProtoGRE || src.String() != "192.0.2.9" || len(rest) != 1 {
		t.Errorf("%v %d %s %d", ok, proto, src, len(rest))
	}
	h[6] = 0x20 // more fragments
	if _, _, _, ok := IPv4Header(h); ok {
		t.Error("accepted a fragment")
	}
}

func TestSLL2(t *testing.T) {
	inner := innerFrame()
	b := append([]byte{0x08, 0x00, 0, 0, 0, 0, 0, 2, 0, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0}, inner[18:]...) // past MAC and VLAN tag
	var p Packet
	if !Decode(LinkLinuxSLL2, b, time.Time{}, &p) || p.DstPort != 5701 {
		t.Errorf("decoded %+v", p)
	}
}

// TestUnwrap finds the mirrored frame inside a captured ERSPAN packet, as a
// capture taken at the mirror's destination holds it.
func TestUnwrap(t *testing.T) {
	inner := innerFrame()
	gre := append(greHeader(0x1000, 0x88be, 4), 0x10, 0, 0, 1, 0, 0, 0, 0)
	gre = append(gre, inner...)
	ip := []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, ProtoGRE, 0, 0, 192, 0, 2, 9, 10, 0, 0, 1}
	outer := append([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00}, append(ip, gre...)...)
	got, ok := Unwrap(LinkEthernet, outer)
	if !ok || !bytes.Equal(got, inner) {
		t.Fatalf("ok %v, %d bytes", ok, len(got))
	}
	udp := []byte{0x13, 0x88, 0x90, 0x90, 0, 0, 0, 0} // to port 37008
	tz := append(append(udp, 1, 0, 0, 1, 1), inner...)
	ip[9] = ProtoUDP
	if got, ok := Unwrap(LinkRaw, append(append([]byte(nil), ip...), tz...)); !ok || !bytes.Equal(got, inner) {
		t.Errorf("TZSP: ok %v, %d bytes", ok, len(got))
	}
}
