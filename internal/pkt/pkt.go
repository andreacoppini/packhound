// Package pkt turns captured frames into the few fields the monitor needs, and
// builds frames back from those fields for the demo source and for recordings
// made without a capture driver.
//
// Only multicast survives decoding: anything whose IP destination is not a
// multicast group is rejected here, so nothing further along has to ask.
package pkt

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// Link-layer types, numbered as pcap numbers them.
const (
	LinkNull     = 0   // BSD loopback: 4-byte host-order address family
	LinkEthernet = 1   // Ethernet II, optionally 802.1Q tagged
	LinkRaw      = 101 // bare IP, version read from the first nibble
	LinkLoop     = 108 // OpenBSD loopback: 4-byte network-order family
	LinkLinuxSLL = 113 // Linux "cooked" capture
)

// IP protocol numbers the monitor tells apart.
const (
	ProtoIGMP   = 2
	ProtoUDP    = 17
	ProtoICMPv6 = 58
	ProtoEIGRP  = 88
	ProtoOSPF   = 89
	ProtoPIM    = 103
	ProtoVRRP   = 112
)

// Fragment says where a datagram sits in IPv4 or IPv6 fragmentation.
type Fragment uint8

const (
	Whole Fragment = iota // not fragmented
	First                 // first fragment: carries the UDP header
	Later                 // any later fragment: no UDP header, no ports
)

// Packet is one multicast IP datagram, reduced to what the monitor reads.
//
// Payload aliases the capture buffer and is only valid until the next packet
// is read: anything kept beyond the call that receives it must be copied.
type Packet struct {
	Time    time.Time
	Src     netip.Addr
	Dst     netip.Addr
	Proto   uint8 // IP protocol (after IPv6 extension headers)
	SrcPort uint16
	DstPort uint16
	IPLen   int    // the whole IP datagram as sent: header plus payload
	Payload []byte // UDP payload for UDP, otherwise the IP payload
	Frag    Fragment
	FragID  uint32 // identification, to tie later fragments to the first
	VLAN    uint16 // 802.1Q VLAN ID, 0 when untagged
}

// IsV6 reports whether the packet is IPv6.
func (p *Packet) IsV6() bool { return p.Dst.Is6() && !p.Dst.Is4In6() }

// Decode reads one frame of the given link type. ok is false for anything that
// is not a multicast IPv4 or IPv6 datagram, or is too short to be one.
func Decode(link int, frame []byte, ts time.Time, p *Packet) (ok bool) {
	*p = Packet{Time: ts}
	switch link {
	case LinkEthernet:
		return decodeEthernet(frame, p)
	case LinkNull:
		if len(frame) < 4 {
			return false
		}
		// The family is in host order, which for every machine this runs
		// on is little-endian. 2 is AF_INET everywhere; AF_INET6 differs.
		switch binary.LittleEndian.Uint32(frame) {
		case 2:
			return decodeIPv4(frame[4:], p)
		case 10, 23, 24, 28, 30:
			return decodeIPv6(frame[4:], p)
		}
		return false
	case LinkLoop:
		if len(frame) < 4 {
			return false
		}
		switch binary.BigEndian.Uint32(frame) {
		case 2:
			return decodeIPv4(frame[4:], p)
		case 24, 28, 30:
			return decodeIPv6(frame[4:], p)
		}
		return false
	case LinkRaw:
		return decodeIP(frame, p)
	case LinkLinuxSLL:
		if len(frame) < 16 {
			return false
		}
		return decodeEtherType(binary.BigEndian.Uint16(frame[14:]), frame[16:], p)
	}
	return false
}

func decodeEthernet(b []byte, p *Packet) bool {
	if len(b) < 14 {
		return false
	}
	// A multicast IP datagram always goes to a group MAC address, which has
	// the low bit of the first octet set. Checking it first throws away the
	// unicast flood on a promiscuous port before any parsing. Linux loopback
	// frames carry an all-zero address, and are let through to the IP check.
	// Broadcast has
	// the bit too, but never carries a multicast IP destination, so the IP
	// check below drops it.
	if b[0]&1 == 0 && !zeroMAC(b[:6]) {
		return false
	}
	et := binary.BigEndian.Uint16(b[12:])
	b = b[14:]
	// 802.1Q and 802.1ad tags, possibly stacked (QinQ). The innermost VLAN
	// is the one kept.
	for (et == 0x8100 || et == 0x88a8 || et == 0x9100) && len(b) >= 4 {
		p.VLAN = binary.BigEndian.Uint16(b) & 0x0fff
		et = binary.BigEndian.Uint16(b[2:])
		b = b[4:]
	}
	return decodeEtherType(et, b, p)
}

func decodeEtherType(et uint16, b []byte, p *Packet) bool {
	switch et {
	case 0x0800:
		return decodeIPv4(b, p)
	case 0x86dd:
		return decodeIPv6(b, p)
	}
	return false
}

func decodeIP(b []byte, p *Packet) bool {
	if len(b) == 0 {
		return false
	}
	switch b[0] >> 4 {
	case 4:
		return decodeIPv4(b, p)
	case 6:
		return decodeIPv6(b, p)
	}
	return false
}

func decodeIPv4(b []byte, p *Packet) bool {
	if len(b) < 20 || b[0]>>4 != 4 {
		return false
	}
	ihl := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:]))
	if ihl < 20 || total < ihl || len(b) < ihl {
		return false
	}
	dst := netip.AddrFrom4([4]byte(b[16:20]))
	if !dst.IsMulticast() {
		return false
	}
	// Ethernet pads short frames to 60 bytes; the IP length is the truth.
	// A frame cut short by the capture's snap length keeps what it has.
	if total < len(b) {
		b = b[:total]
	}
	p.Src = netip.AddrFrom4([4]byte(b[12:16]))
	p.Dst = dst
	p.Proto = b[9]
	p.IPLen = total

	flags := binary.BigEndian.Uint16(b[6:])
	off := flags & 0x1fff
	more := flags&0x2000 != 0
	if off != 0 || more {
		p.FragID = uint32(binary.BigEndian.Uint16(b[4:]))
		if off != 0 {
			p.Frag = Later
			p.Payload = b[ihl:]
			return true
		}
		p.Frag = First
	}
	return decodeL4(b[ihl:], p)
}

func decodeIPv6(b []byte, p *Packet) bool {
	if len(b) < 40 || b[0]>>4 != 6 {
		return false
	}
	dst := netip.AddrFrom16([16]byte(b[24:40]))
	if !dst.IsMulticast() {
		return false
	}
	plen := int(binary.BigEndian.Uint16(b[4:]))
	if 40+plen < len(b) {
		b = b[:40+plen]
	}
	p.Src = netip.AddrFrom16([16]byte(b[8:24]))
	p.Dst = dst
	p.IPLen = 40 + plen

	next := b[6]
	rest := b[40:]
	// Walk the extension headers. MLD always arrives behind a hop-by-hop
	// header carrying the router-alert option, so this is not optional.
	for {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(rest) < 8 {
				return false
			}
			n := (int(rest[1]) + 1) * 8
			if len(rest) < n {
				return false
			}
			next, rest = rest[0], rest[n:]
			continue
		case 44: // fragment
			if len(rest) < 8 {
				return false
			}
			offFlags := binary.BigEndian.Uint16(rest[2:])
			p.FragID = binary.BigEndian.Uint32(rest[4:])
			next = rest[0]
			rest = rest[8:]
			if offFlags>>3 != 0 {
				p.Proto = next
				p.Frag = Later
				p.Payload = rest
				return true
			}
			if offFlags&1 != 0 {
				p.Frag = First
			}
			continue
		}
		break
	}
	p.Proto = next
	return decodeL4(rest, p)
}

func decodeL4(b []byte, p *Packet) bool {
	if p.Proto != ProtoUDP {
		p.Payload = b
		return true
	}
	if len(b) < 8 {
		return false
	}
	p.SrcPort = binary.BigEndian.Uint16(b)
	p.DstPort = binary.BigEndian.Uint16(b[2:])
	ul := int(binary.BigEndian.Uint16(b[4:]))
	b = b[8:]
	// The UDP length bounds the payload when the datagram is whole. A first
	// fragment's UDP length describes the reassembled datagram, so it is
	// larger than what is here, and the bound does not apply.
	if p.Frag == Whole && ul >= 8 && ul-8 < len(b) {
		b = b[:ul-8]
	}
	p.Payload = b
	return true
}

func zeroMAC(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
