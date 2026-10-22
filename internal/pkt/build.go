package pkt

import (
	"encoding/binary"
	"net/netip"
)

// GroupMAC is the Ethernet address a multicast group is sent to:
// 01:00:5e plus the low 23 bits for IPv4, 33:33 plus the low 32 bits for IPv6.
func GroupMAC(g netip.Addr) [6]byte {
	if g.Is4() {
		a := g.As4()
		return [6]byte{0x01, 0x00, 0x5e, a[1] & 0x7f, a[2], a[3]}
	}
	a := g.As16()
	return [6]byte{0x33, 0x33, a[12], a[13], a[14], a[15]}
}

// Spec describes a datagram to build.
type Spec struct {
	Src, Dst         netip.Addr
	SrcMAC           [6]byte
	Proto            uint8 // ProtoUDP unless set
	SrcPort, DstPort uint16
	TTL              uint8 // 1 unless set; IPv6 hop limit too
	RouterAlert      bool  // IPv6 hop-by-hop router alert, as MLD carries
	Payload          []byte
}

// Frame builds an Ethernet frame carrying one IP datagram. It is how the demo
// source produces traffic, and how a recording made without a capture driver
// gets frames to write: the receiving socket only ever saw the payload.
//
// Checksums are left at zero, which pcap readers accept and the decoder never
// looks at. IPv4 datagrams over the Ethernet MTU are not fragmented.
func Frame(s Spec) []byte {
	if s.Proto == 0 {
		s.Proto = ProtoUDP
	}
	if s.TTL == 0 {
		s.TTL = 1
	}
	l4 := s.Payload
	if s.Proto == ProtoUDP {
		u := make([]byte, 8+len(s.Payload))
		binary.BigEndian.PutUint16(u, s.SrcPort)
		binary.BigEndian.PutUint16(u[2:], s.DstPort)
		binary.BigEndian.PutUint16(u[4:], uint16(len(u)))
		copy(u[8:], s.Payload)
		l4 = u
	}

	dmac := GroupMAC(s.Dst)
	var b []byte
	if s.Dst.Is4() {
		b = make([]byte, 14+20+len(l4))
		binary.BigEndian.PutUint16(b[12:], 0x0800)
		ip := b[14:]
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
		ip[8] = s.TTL
		ip[9] = s.Proto
		src, dst := s.Src.As4(), s.Dst.As4()
		copy(ip[12:], src[:])
		copy(ip[16:], dst[:])
		copy(ip[20:], l4)
	} else {
		ext := 0
		if s.RouterAlert {
			ext = 8
		}
		b = make([]byte, 14+40+ext+len(l4))
		binary.BigEndian.PutUint16(b[12:], 0x86dd)
		ip := b[14:]
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:], uint16(ext+len(l4)))
		ip[7] = s.TTL
		src, dst := s.Src.As16(), s.Dst.As16()
		copy(ip[8:], src[:])
		copy(ip[24:], dst[:])
		if s.RouterAlert {
			ip[6] = 0 // hop-by-hop
			h := ip[40:48]
			h[0] = s.Proto
			h[1] = 0
			h[2], h[3] = 5, 2 // router alert option, MLD
			h[6], h[7] = 1, 0 // PadN, no padding bytes
			copy(ip[48:], l4)
		} else {
			ip[6] = s.Proto
			copy(ip[40:], l4)
		}
	}
	copy(b[0:6], dmac[:])
	copy(b[6:12], s.SrcMAC[:])
	return b
}

// Rebuild makes a frame from a decoded packet, for packets that arrived on a
// socket rather than through capture. Later fragments cannot be rebuilt; the
// socket never delivers them anyway.
func Rebuild(p *Packet) []byte {
	return Frame(Spec{
		Src: p.Src, Dst: p.Dst, Proto: p.Proto,
		SrcPort: p.SrcPort, DstPort: p.DstPort,
		Payload: p.Payload,
	})
}
