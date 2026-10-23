package pkt

import (
	"encoding/binary"
	"net/netip"
)

// Remote mirroring: a switch copies a port's traffic and sends it, wrapped,
// to an address of ours. The wrappers peeled here leave the original
// Ethernet frame, which then decodes like any other.

// ProtoGRE is the IP protocol of GRE, which carries ERSPAN.
const ProtoGRE = 47

// TZSPPort is where MikroTik and others send TZSP-wrapped mirrored frames.
const TZSPPort = 37008

// IPv4Header reads an IPv4 header, as a raw socket delivers it, for the
// protocol, the source and what follows the header. The length fields are
// not trusted: BSD raw sockets rewrite them in host order.
func IPv4Header(b []byte) (proto uint8, src netip.Addr, payload []byte, ok bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return 0, netip.Addr{}, nil, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || ihl > len(b) {
		return 0, netip.Addr{}, nil, false
	}
	// A fragment of a mirrored frame cannot be read on its own.
	if binary.BigEndian.Uint16(b[6:])&0x3fff != 0 {
		return 0, netip.Addr{}, nil, false
	}
	return b[9], netip.AddrFrom4([4]byte(b[12:16])), b[ihl:], true
}

// GRE peels a GRE packet (everything after the IP header) carrying mirrored
// traffic, and returns the Ethernet frame inside. session is the ERSPAN
// session ID, or -1 when the encapsulation has none. It reads:
//
//   - ERSPAN Type I: protocol 0x88BE, no sequence number, Ethernet follows.
//   - ERSPAN Type II: protocol 0x88BE with a sequence number, then an
//     8-byte ERSPAN header.
//   - ERSPAN Type III: protocol 0x22EB, a 12-byte header, and an 8-byte
//     platform subheader when its O bit is set.
//   - Transparent Ethernet bridging: protocol 0x6558, Ethernet follows.
func GRE(b []byte) (frame []byte, session int, ok bool) {
	if len(b) < 4 {
		return nil, -1, false
	}
	flags := binary.BigEndian.Uint16(b)
	if flags&0x0007 != 0 { // GRE version 0 only
		return nil, -1, false
	}
	proto := binary.BigEndian.Uint16(b[2:])
	n := 4
	if flags&0x8000 != 0 { // checksum
		n += 4
	}
	if flags&0x2000 != 0 { // key
		n += 4
	}
	seq := flags&0x1000 != 0
	if seq {
		n += 4
	}
	if len(b) < n {
		return nil, -1, false
	}
	b = b[n:]
	session = -1
	switch proto {
	case 0x6558:
	case 0x88be:
		if seq { // Type II
			if len(b) < 8 || b[0]>>4 != 1 {
				return nil, -1, false
			}
			session = int(b[2]&0x03)<<8 | int(b[3])
			b = b[8:]
		}
	case 0x22eb: // Type III
		if len(b) < 12 || b[0]>>4 != 2 {
			return nil, -1, false
		}
		if (b[10]>>2)&0x1f != 0 { // frame type: only Ethernet
			return nil, -1, false
		}
		session = int(b[2]&0x03)<<8 | int(b[3])
		h := 12
		if b[11]&1 != 0 {
			h += 8
		}
		if len(b) < h {
			return nil, -1, false
		}
		b = b[h:]
	default:
		return nil, -1, false
	}
	if len(b) < 14 {
		return nil, -1, false
	}
	return b, session, true
}

// TZSP peels a TZSP datagram (the UDP payload) and returns the Ethernet
// frame inside: version 1, a received packet, Ethernet encapsulation, after
// the tagged fields.
func TZSP(b []byte) (frame []byte, ok bool) {
	if len(b) < 4 || b[0] != 1 || b[1] != 0 || binary.BigEndian.Uint16(b[2:]) != 1 {
		return nil, false
	}
	b = b[4:]
	for len(b) > 0 {
		switch b[0] {
		case 0: // padding
			b = b[1:]
			continue
		case 1: // end of the fields
			b = b[1:]
			if len(b) < 14 {
				return nil, false
			}
			return b, true
		}
		if len(b) < 2 || len(b) < 2+int(b[1]) {
			return nil, false
		}
		b = b[2+int(b[1]):]
	}
	return nil, false
}

// Unwrap finds mirrored traffic inside a captured frame: a frame of the
// given link type carrying GRE (ERSPAN) or TZSP, as a capture taken where
// a switch's mirror arrives contains. It returns the Ethernet frame inside.
func Unwrap(link int, frame []byte) ([]byte, bool) {
	inner, _, _, ok := UnwrapFrame(link, frame)
	return inner, ok
}

// UnwrapFrame is Unwrap, also returning the switch that sent the mirror and
// its ERSPAN session (-1 for none).
func UnwrapFrame(link int, frame []byte) (inner []byte, src netip.Addr, session int, ok bool) {
	var ip []byte
	switch link {
	case LinkEthernet:
		if len(frame) < 14 {
			return nil, netip.Addr{}, -1, false
		}
		et, b := binary.BigEndian.Uint16(frame[12:]), frame[14:]
		for (et == 0x8100 || et == 0x88a8 || et == 0x9100) && len(b) >= 4 {
			et, b = binary.BigEndian.Uint16(b[2:]), b[4:]
		}
		if et != 0x0800 {
			return nil, netip.Addr{}, -1, false
		}
		ip = b
	case LinkLinuxSLL:
		if len(frame) < 16 || binary.BigEndian.Uint16(frame[14:]) != 0x0800 {
			return nil, netip.Addr{}, -1, false
		}
		ip = frame[16:]
	case LinkLinuxSLL2:
		if len(frame) < 20 || binary.BigEndian.Uint16(frame) != 0x0800 {
			return nil, netip.Addr{}, -1, false
		}
		ip = frame[20:]
	case LinkRaw:
		ip = frame
	case LinkNull, LinkLoop: // BSD loopback: a 4-byte address family
		if len(frame) < 4 || (binary.LittleEndian.Uint32(frame) != 2 && binary.BigEndian.Uint32(frame) != 2) {
			return nil, netip.Addr{}, -1, false
		}
		ip = frame[4:]
	default:
		return nil, netip.Addr{}, -1, false
	}
	proto, src, rest, ok := IPv4Header(ip)
	if !ok {
		return nil, netip.Addr{}, -1, false
	}
	switch proto {
	case ProtoGRE:
		inner, session, ok = GRE(rest)
		return inner, src, session, ok
	case ProtoUDP:
		if len(rest) < 8 || binary.BigEndian.Uint16(rest[2:]) != TZSPPort {
			return nil, netip.Addr{}, -1, false
		}
		inner, ok = TZSP(rest[8:])
		return inner, src, -1, ok
	}
	return nil, netip.Addr{}, -1, false
}
