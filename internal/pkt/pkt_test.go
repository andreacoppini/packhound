package pkt

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestRoundTripIPv4UDP(t *testing.T) {
	payload := bytes.Repeat([]byte{0x47}, 1316)
	f := Frame(Spec{
		Src: netip.MustParseAddr("10.20.0.11"), Dst: netip.MustParseAddr("239.10.1.1"),
		SrcPort: 40000, DstPort: 5000, Payload: payload,
	})
	if got := f[:6]; !bytes.Equal(got, []byte{1, 0, 0x5e, 10, 1, 1}) {
		t.Fatalf("group MAC = % x", got)
	}
	var p Packet
	if !Decode(LinkEthernet, f, time.Unix(1, 0), &p) {
		t.Fatal("not decoded")
	}
	if p.Dst.String() != "239.10.1.1" || p.Src.String() != "10.20.0.11" || p.Proto != ProtoUDP ||
		p.DstPort != 5000 || p.SrcPort != 40000 || p.IPLen != 1344 || len(p.Payload) != 1316 || p.Frag != Whole {
		t.Fatalf("decoded %+v", p)
	}
}

func TestEthernetPaddingIsIgnored(t *testing.T) {
	f := Frame(Spec{
		Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("224.0.0.1"),
		Proto: ProtoIGMP, Payload: []byte{0x11, 0x64, 0, 0, 0, 0, 0, 0},
	})
	f = append(f, make([]byte, 60-len(f))...) // what the NIC delivers
	var p Packet
	if !Decode(LinkEthernet, f, time.Time{}, &p) {
		t.Fatal("not decoded")
	}
	if len(p.Payload) != 8 || p.IPLen != 28 {
		t.Fatalf("payload %d bytes, IP length %d; padding leaked in", len(p.Payload), p.IPLen)
	}
}

func TestLinuxLoopbackZeroMAC(t *testing.T) {
	f := Frame(Spec{Src: netip.MustParseAddr("127.0.0.1"), Dst: netip.MustParseAddr("239.1.2.3"), DstPort: 5000, Payload: []byte("x")})
	copy(f[:12], make([]byte, 12))
	var p Packet
	if !Decode(LinkEthernet, f, time.Time{}, &p) || p.DstPort != 5000 {
		t.Fatalf("loopback frame not decoded: %+v", p)
	}
}

func TestVLANTagged(t *testing.T) {
	f := Frame(Spec{
		Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("239.1.1.1"),
		DstPort: 1234, Payload: []byte("hi"),
	})
	tagged := append([]byte{}, f[:12]...)
	tagged = append(tagged, 0x81, 0x00, 0x00, 0x64) // VLAN 100
	tagged = append(tagged, f[12:]...)
	var p Packet
	if !Decode(LinkEthernet, tagged, time.Time{}, &p) || p.VLAN != 100 || string(p.Payload) != "hi" {
		t.Fatalf("decoded %v %+v", p.VLAN, p)
	}
}

func TestUnicastAndBroadcastRejected(t *testing.T) {
	var p Packet
	uni := Frame(Spec{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("239.1.1.1"), Payload: []byte("x")})
	uni[0] = 0x00 // unicast MAC
	if Decode(LinkEthernet, uni, time.Time{}, &p) {
		t.Fatal("unicast frame accepted")
	}
	bc := Frame(Spec{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("239.1.1.1"), Payload: []byte("x")})
	copy(bc[:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(bc[14+16:], []byte{10, 0, 0, 255}) // directed broadcast
	if Decode(LinkEthernet, bc, time.Time{}, &p) {
		t.Fatal("broadcast accepted")
	}
}

func TestIPv6HopByHopICMPv6(t *testing.T) {
	f := Frame(Spec{
		Src: netip.MustParseAddr("fe80::1"), Dst: netip.MustParseAddr("ff02::16"),
		Proto: ProtoICMPv6, RouterAlert: true, Payload: []byte{143, 0, 0, 0, 0, 0, 0, 0},
	})
	var p Packet
	if !Decode(LinkEthernet, f, time.Time{}, &p) {
		t.Fatal("not decoded")
	}
	if p.Proto != ProtoICMPv6 || p.Payload[0] != 143 || !p.IsV6() {
		t.Fatalf("decoded %+v", p)
	}
}

func TestIPv4Fragments(t *testing.T) {
	f := Frame(Spec{
		Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("239.1.1.1"),
		DstPort: 5000, Payload: make([]byte, 100),
	})
	ip := f[14:]
	binary.BigEndian.PutUint16(ip[4:], 77)
	binary.BigEndian.PutUint16(ip[6:], 0x2000) // more fragments, offset 0
	var p Packet
	if !Decode(LinkEthernet, f, time.Time{}, &p) || p.Frag != First || p.FragID != 77 || p.DstPort != 5000 {
		t.Fatalf("first fragment %+v", p)
	}
	binary.BigEndian.PutUint16(ip[6:], 185) // offset 1480, last
	if !Decode(LinkEthernet, f, time.Time{}, &p) || p.Frag != Later || p.DstPort != 0 || p.FragID != 77 {
		t.Fatalf("later fragment %+v", p)
	}
}

func TestLinuxCooked(t *testing.T) {
	f := Frame(Spec{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("224.0.0.251"), DstPort: 5353, Payload: []byte("q")})
	sll := make([]byte, 16)
	binary.BigEndian.PutUint16(sll[14:], 0x0800)
	sll = append(sll, f[14:]...)
	var p Packet
	if !Decode(LinkLinuxSLL, sll, time.Time{}, &p) || p.DstPort != 5353 {
		t.Fatalf("decoded %+v", p)
	}
}
