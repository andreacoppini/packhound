package monitor

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/andreacoppini/packhound/internal/mpegts"
	"github.com/andreacoppini/packhound/internal/pkt"
)

// decoder reads one protocol's payloads for a stream. It runs under the
// monitor's lock, and must copy anything it keeps from a payload.
type decoder interface {
	feed(s *Stream, p *pkt.Packet)
	tick(s *Stream, now time.Time)
	// name is a human label for the stream ("BBC One HD", "21 services").
	name(s *Stream) string
	// errorsLastMinute is the count that makes a media stream Degraded, and
	// what to call it; an empty label means the protocol has no such count.
	errorsLastMinute() (uint64, string)
	describe(s *Stream, d *Detail)
}

// KV is one labelled fact in the detail panel.
type KV struct {
	K string `json:"k"`
	V string `json:"v"`
}

// Table is a protocol-specific table in the detail panel.
type Table struct {
	Title string     `json:"title"`
	Cols  []string   `json:"cols"`
	Rows  [][]string `json:"rows"`
}

// Detail is the protocol-specific part of a stream's detail panel.
type Detail struct {
	KV     []KV    `json:"kv"`
	Tables []Table `json:"tables"`
}

func (d *Detail) add(k, v string) {
	if v != "" {
		d.KV = append(d.KV, KV{k, v})
	}
}

// base gives decoders that do not need them empty methods.
type base struct{}

func (base) tick(*Stream, time.Time)            {}
func (base) name(*Stream) string                { return "" }
func (base) errorsLastMinute() (uint64, string) { return 0, "" }

// window counts events per second over the last minute.
type window struct {
	secs [60]uint32
	cur  uint32
	idx  int
}

func (w *window) add(n uint32) { w.cur += n }

func (w *window) roll() {
	w.idx = (w.idx + 1) % len(w.secs)
	w.secs[w.idx] = w.cur
	w.cur = 0
}

func (w *window) minute() uint64 {
	n := uint64(w.cur)
	for _, c := range w.secs {
		n += uint64(c)
	}
	return n
}

// perSecond is the average over the last n whole seconds.
func (w *window) perSecond(n int) float64 {
	var t uint32
	for i := 0; i < n; i++ {
		t += w.secs[(w.idx-i+len(w.secs))%len(w.secs)]
	}
	return float64(t) / float64(n)
}

func ago(now, t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := now.Sub(t)
	switch {
	case d < time.Second:
		return "now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm %ds ago", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm ago", int(d.Hours()), int(d.Minutes())%60)
}

// ---- classification ----

// classify decides what a stream is from its key and first packet.
func classify(m *Monitor, k Key, p *pkt.Packet) (Kind, string, decoder) {
	switch k.Proto {
	case pkt.ProtoIGMP:
		return KindNetwork, "IGMP", &igmpDec{}
	case pkt.ProtoVRRP:
		return KindNetwork, "VRRP", &vrrpDec{}
	case pkt.ProtoOSPF:
		return KindNetwork, "OSPF", &genericDec{label: "OSPF routers"}
	case pkt.ProtoPIM:
		return KindNetwork, "PIM", &genericDec{label: "PIM routers"}
	case pkt.ProtoEIGRP:
		return KindNetwork, "EIGRP", &genericDec{label: "EIGRP routers"}
	case pkt.ProtoICMPv6:
		return KindNetwork, "ICMPv6", newICMP6(k)
	case pkt.ProtoUDP:
	default:
		return KindUnknown, fmt.Sprintf("IP protocol %d", k.Proto), &genericDec{}
	}

	switch k.Port {
	case 5353:
		return KindDiscovery, "mDNS", newDNS(true)
	case 5355:
		return KindDiscovery, "LLMNR", newDNS(false)
	case 1900:
		return KindDiscovery, "SSDP / UPnP", newSSDP()
	case 3702:
		return KindDiscovery, "WS-Discovery", newWSD()
	case 9875:
		return KindDiscovery, "SAP / SDP", newSAP()
	case 319, 320:
		return KindTiming, "PTP", newPTP()
	case 123:
		return KindTiming, "NTP", &genericDec{label: "NTP broadcast"}
	case 520, 521:
		return KindNetwork, "RIP", &genericDec{label: "RIP routers"}
	case 1985:
		return KindNetwork, "HSRP", newHSRP()
	case 546, 547:
		return KindNetwork, "DHCPv6", &genericDec{label: "DHCPv6"}
	case 427:
		return KindDiscovery, "SLP", &genericDec{label: "Service Location Protocol"}
	case 5683:
		return KindDiscovery, "CoAP", &genericDec{label: "CoAP discovery"}
	case 6771:
		return KindDiscovery, "BitTorrent LSD", &genericDec{label: "BitTorrent local peer discovery"}
	case 21027:
		return KindDiscovery, "Syncthing", &genericDec{label: "Syncthing discovery"}
	case 8700, 8701, 8702, 8703, 8704, 8705, 8706, 8707, 8708:
		if k.Dst.Is4() && k.Dst.As4()[0] == 224 {
			return KindDiscovery, "Dante control", &genericDec{label: "Dante device control", byDevice: true}
		}
	case 4321:
		if k.Dst.Is4() {
			if a := k.Dst.As4(); a[0] == 239 && a[1] == 255 {
				return KindAudio, "Dante audio", &genericDec{label: "Dante multicast flow", byDevice: true}
			}
		}
	}

	b := p.Payload
	if p.Frag != pkt.Later {
		if mpegts.LooksLikeTS(b) {
			return KindVideo, "MPEG-TS / UDP", newTS()
		}
		if r, ok := rtpHeader(b); ok {
			d := newRTP(r.pt, r.payload)
			kind, typ := d.classify(m, k)
			return kind, typ, d
		}
	}
	return KindUnknown, "UDP", &genericDec{}
}

// ---- generic ----

// genericDec is for protocols that are only counted: it keeps the first
// bytes of the latest packet so the operator can see what it is.
type genericDec struct {
	base
	label string
	// byDevice adds the sending device's announced name to the label, so a
	// device's flows group together when sorted by name.
	byDevice bool
	head     []byte
	size     int
}

func (g *genericDec) feed(_ *Stream, p *pkt.Packet) {
	n := len(p.Payload)
	if n > 32 {
		n = 32
	}
	g.head = append(g.head[:0], p.Payload[:n]...)
	g.size = len(p.Payload)
}

func (g *genericDec) name(s *Stream) string {
	if g.label != "" {
		if g.byDevice {
			if dev := s.deviceName(); dev != "" {
				return dev + " · " + g.label
			}
		}
		return g.label
	}
	return "(unrecognised payload)"
}

func (g *genericDec) describe(s *Stream, d *Detail) {
	if g.label == "" {
		d.add("Payload", "no RTP header, MPEG-TS sync or known port")
	}
	if len(g.head) > 0 {
		d.add("Latest payload", fmt.Sprintf("%d bytes", g.size))
		d.add("First bytes", hexDump(g.head))
	}
}

func hexDump(b []byte) string {
	var h, a strings.Builder
	for i, c := range b {
		if i == 16 {
			break
		}
		fmt.Fprintf(&h, "%02x ", c)
		if c >= 0x20 && c < 0x7f {
			a.WriteByte(c)
		} else {
			a.WriteByte('.')
		}
	}
	return strings.TrimSpace(h.String()) + "  " + a.String()
}

func u16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }
func u32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }
