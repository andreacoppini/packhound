// Package demo makes believable multicast traffic for trying the console
// without a network to point it at: IPTV channels (one with continuity errors,
// one that drops out), AES67 audio with its SAP announcements, and the
// discovery, timing and routing chatter of a real site.
//
// Every frame is a real Ethernet frame that goes through the same decoding as
// captured traffic, so the demo exercises the whole pipeline.
package demo

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/andreacoppini/packhound/internal/mpegts"
	"github.com/andreacoppini/packhound/internal/pkt"
)

// Source yields demo frames in real time.
type Source struct {
	start  time.Time
	gens   []*gen
	rnd    *rand.Rand
	mu     sync.Mutex
	closed chan struct{}
	once   sync.Once
}

// gen is one traffic generator: it says when its next frame is due, and
// makes it.
type gen struct {
	next time.Time
	make func(now time.Time) (frame []byte, wait time.Duration)
}

func New() *Source {
	s := &Source{start: time.Now(), rnd: rand.New(rand.NewSource(1)), closed: make(chan struct{})}
	s.build()
	return s
}

// Next blocks until the next frame is due and returns it.
func (s *Source) Next() ([]byte, time.Time, error) {
	for {
		var g *gen
		for _, x := range s.gens {
			if g == nil || x.next.Before(g.next) {
				g = x
			}
		}
		if d := time.Until(g.next); d > time.Millisecond {
			select {
			case <-s.closed:
				return nil, time.Time{}, errClosed
			case <-time.After(d):
			}
		}
		select {
		case <-s.closed:
			return nil, time.Time{}, errClosed
		default:
		}
		now := time.Now()
		f, wait := g.make(now)
		g.next = g.next.Add(wait)
		// After a stall (a sleeping laptop), do not try to catch up by
		// sending a burst of everything that was missed.
		if g.next.Before(now.Add(-time.Second)) {
			g.next = now.Add(wait)
		}
		if f != nil {
			return f, now, nil
		}
	}
}

type closedErr struct{}

func (closedErr) Error() string { return "demo source closed" }

var errClosed = closedErr{}

func (s *Source) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

func (s *Source) add(first time.Duration, f func(now time.Time) ([]byte, time.Duration)) {
	s.gens = append(s.gens, &gen{next: s.start.Add(first), make: f})
}

func ip(a string) netip.Addr { return netip.MustParseAddr(a) }

func mac(a netip.Addr) [6]byte {
	b := a.AsSlice()
	return [6]byte{0x02, 0x50, b[len(b)-4], b[len(b)-3], b[len(b)-2], b[len(b)-1]}
}

func udp(src, dst string, sport, dport uint16, payload []byte) []byte {
	s, d := ip(src), ip(dst)
	return pkt.Frame(pkt.Spec{Src: s, Dst: d, SrcMAC: mac(s), SrcPort: sport, DstPort: dport, Payload: payload, TTL: 8})
}

func raw(src, dst string, proto uint8, alert bool, payload []byte) []byte {
	s, d := ip(src), ip(dst)
	return pkt.Frame(pkt.Spec{Src: s, Dst: d, SrcMAC: mac(s), Proto: proto, RouterAlert: alert, Payload: payload})
}

// since is how far into the demo now is, for scripted events.
func (s *Source) since(now time.Time) time.Duration { return now.Sub(s.start) }

func (s *Source) build() {
	// IPTV, as a headend sends it.
	s.channel(channelSpec{group: "239.10.1.1", src: "10.20.0.11", name: "BBC One HD", provider: "BBC", program: 17472, pmt: 0x64, video: 0x65, mbps: 8.4, w: 1920, h: 1080, interlaced: true})
	s.channel(channelSpec{group: "239.10.1.2", src: "10.20.0.11", name: "ITV1 HD", provider: "ITV", program: 8270, pmt: 0x100, video: 0x101, mbps: 7.9, w: 1920, h: 1080, interlaced: true})
	s.channel(channelSpec{group: "239.10.1.3", src: "10.20.0.11", name: "Channel 4 HD", provider: "Channel 4", program: 8384, pmt: 0x100, video: 0x101, mbps: 9.1, w: 1920, h: 1080, interlaced: true, rtp: true, rtpGapEvery: 100 * time.Second})
	s.channel(channelSpec{group: "239.10.1.7", src: "10.20.0.12", name: "Sky Sports Main Event", provider: "Sky", program: 4002, pmt: 0x1000, video: 0x200, mbps: 8.8, w: 1920, h: 1080, interlaced: true,
		// Drops out for 25 seconds of every two minutes, 40 seconds in.
		off: func(t time.Duration) bool { t %= 2 * time.Minute; return t > 40*time.Second && t < 65*time.Second }})
	s.channel(channelSpec{group: "239.10.2.20", port: 5004, src: "10.20.4.31", name: "Signage-Lobby", provider: "Signage", program: 1, pmt: 0x1000, video: 0x100, mbps: 3.2, w: 1280, h: 720,
		ccErrorProb: 0.00015,
		// Sags to a third of its rate for nine seconds every minute.
		scale: func(t time.Duration) float64 {
			if t%time.Minute > 30*time.Second && t%time.Minute < 39*time.Second {
				return 0.35
			}
			return 1
		}})

	s.aes67()
	s.sap()
	s.mdns()
	s.ssdp()
	s.wsd()
	s.llmnr()
	s.ptp()
	s.igmp()
	s.vrrp()
	s.unknown()
	s.ipv6()
}

// ---- IPTV ----

type channelSpec struct {
	group, src     string
	port           uint16
	name, provider string
	program        uint16
	pmt, video     uint16
	mbps           float64
	w, h           int
	interlaced     bool
	rtp            bool
	rtpGapEvery    time.Duration
	ccErrorProb    float64
	off            func(time.Duration) bool
	scale          func(time.Duration) float64
}

func (s *Source) channel(c channelSpec) {
	if c.port == 0 {
		c.port = 5000
	}
	m := mpegts.NewMuxer()
	rnd := rand.New(rand.NewSource(int64(c.program)))
	if c.ccErrorProb > 0 {
		m.SkipCC = func(pid uint16) bool { return pid == c.video && rnd.Float64() < c.ccErrorProb }
	}
	audio := c.video + 1
	pat := mpegts.PAT(1, c.program, c.pmt)
	pmt := mpegts.PMT(c.program, c.video, []mpegts.ES{
		{Type: 0x1b, PID: c.video},
		{Type: 0x0f, PID: audio, Lang: "eng"},
		{Type: 0x06, PID: audio + 1, Lang: "eng", Desc: []byte{0x6a, 1, 0}},
	})
	sdt := mpegts.SDT(1, 0x233a, c.program, 0x19, c.provider, c.name)
	sps := mpegts.SPS(c.w, c.h, c.interlaced)

	var queue [][]byte
	var lastPSI, lastSDT, lastFrame, lastAudio time.Time
	frames := 0
	filler := make([]byte, 64<<10)
	for i := range filler {
		filler[i] = 0xa5
	}
	var seq uint16
	var lastGap time.Duration
	ssrc := uint32(c.program) * 7919

	dgram := 7 * mpegts.PacketSize
	s.add(time.Duration(rnd.Intn(5))*time.Millisecond, func(now time.Time) ([]byte, time.Duration) {
		t := s.since(now)
		rate := c.mbps * 1e6
		if c.scale != nil {
			rate *= c.scale(t)
		}
		wait := time.Duration(float64(dgram*8) / rate * float64(time.Second))
		if c.off != nil && c.off(t) {
			return nil, wait
		}
		if now.Sub(lastPSI) >= 100*time.Millisecond {
			queue = append(queue, m.Section(0, pat)...)
			queue = append(queue, m.Section(c.pmt, pmt)...)
			lastPSI = now
		}
		if now.Sub(lastSDT) >= 2*time.Second {
			queue = append(queue, m.Section(0x11, sdt)...)
			lastSDT = now
		}
		if now.Sub(lastAudio) >= 24*time.Millisecond {
			queue = append(queue, m.PES(audio, 0xc0, filler[:576])...)
			queue = append(queue, m.PES(audio+1, 0xbd, filler[:1536])...)
			lastAudio = now
		}
		if now.Sub(lastFrame) >= 40*time.Millisecond && len(queue) < 400 {
			size := int(rate * 0.86 / 8 / 25)
			es := filler[:size]
			if frames%25 == 0 { // a keyframe, with its parameter sets
				es = append(append([]byte{0, 0, 0, 1}, sps...), append([]byte{0, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80, 0, 0, 0, 1, 0x65}, filler[:size]...)...)
			}
			queue = append(queue, m.PES(c.video, 0xe0, es)...)
			frames++
			lastFrame = now
		}
		payload := make([]byte, 0, dgram+12)
		if c.rtp {
			h := make([]byte, 12)
			h[0], h[1] = 0x80, 33
			if c.rtpGapEvery > 0 && t-lastGap > c.rtpGapEvery {
				seq += 2 // one lost on the way
				lastGap = t
			}
			binary.BigEndian.PutUint16(h[2:], seq)
			binary.BigEndian.PutUint32(h[4:], uint32(t.Seconds()*90000))
			binary.BigEndian.PutUint32(h[8:], ssrc)
			seq++
			payload = append(payload, h...)
		}
		for i := 0; i < 7; i++ {
			if len(queue) > 0 {
				payload = append(payload, queue[0]...)
				queue = queue[1:]
			} else {
				payload = append(payload, m.Null()...)
			}
		}
		return udp(c.src, c.group, 49152+uint16(c.program%1000), c.port, payload), wait
	})
}

// ---- AES67 ----

func (s *Source) aes67() {
	var seq uint16
	var ts uint32
	payload := make([]byte, 12+48*2*3) // 1 ms of 2-channel 24-bit audio
	s.add(0, func(now time.Time) ([]byte, time.Duration) {
		b := append([]byte(nil), payload...)
		b[0], b[1] = 0x80, 97
		binary.BigEndian.PutUint16(b[2:], seq)
		binary.BigEndian.PutUint32(b[4:], ts)
		binary.BigEndian.PutUint32(b[8:], 0x5a17c0de)
		seq++
		ts += 48
		return udp("10.20.6.12", "239.69.83.67", 5004, 5004, b), time.Millisecond
	})
}

func (s *Source) sap() {
	announce := func(src, group, name, format string, ptime string) []byte {
		sdp := fmt.Sprintf("v=0\r\no=- 1 1 IN IP4 %s\r\ns=%s\r\nc=IN IP4 %s/32\r\nt=0 0\r\nm=audio 5004 RTP/AVP 97\r\na=rtpmap:97 %s\r\na=ptime:%s\r\n", src, name, group, format, ptime)
		h := []byte{0x20, 0, 0x12, 0x34}
		h = append(h, ip(src).AsSlice()...)
		h = append(h, "application/sdp\x00"...)
		return udp(src, "239.255.255.255", 9875, 9875, append(h, sdp...))
	}
	i := 0
	s.add(200*time.Millisecond, func(now time.Time) ([]byte, time.Duration) {
		i++
		if i%2 == 0 {
			return announce("10.20.6.12", "239.69.83.67", "Bar-Mix", "L24/48000/2", "1"), 2500 * time.Millisecond
		}
		return announce("10.20.6.14", "239.69.83.68", "Stage-Left", "L24/48000/8", "1"), 2500 * time.Millisecond
	})
}

// ---- mDNS ----

type dnsBuilder struct{ b []byte }

func newDNS(response bool, qd, an int) *dnsBuilder {
	h := make([]byte, 12)
	if response {
		h[2] = 0x84
	}
	binary.BigEndian.PutUint16(h[4:], uint16(qd))
	binary.BigEndian.PutUint16(h[6:], uint16(an))
	return &dnsBuilder{b: h}
}

func (d *dnsBuilder) name(n string) {
	for _, l := range strings.Split(strings.TrimSuffix(n, "."), ".") {
		d.b = append(d.b, byte(len(l)))
		d.b = append(d.b, l...)
	}
	d.b = append(d.b, 0)
}

func (d *dnsBuilder) question(n string, typ uint16) {
	d.name(n)
	d.b = binary.BigEndian.AppendUint16(d.b, typ)
	d.b = binary.BigEndian.AppendUint16(d.b, 1)
}

func (d *dnsBuilder) rr(n string, typ uint16, rdata func()) {
	d.name(n)
	d.b = binary.BigEndian.AppendUint16(d.b, typ)
	d.b = binary.BigEndian.AppendUint16(d.b, 0x8001)
	d.b = binary.BigEndian.AppendUint32(d.b, 120)
	at := len(d.b)
	d.b = append(d.b, 0, 0)
	rdata()
	binary.BigEndian.PutUint16(d.b[at:], uint16(len(d.b)-at-2))
}

type mdnsHost struct {
	addr, host, instance, stype string
	port                        uint16
}

func (s *Source) mdns() {
	hosts := []mdnsHost{
		{"10.20.3.40", "Lobby-ATV", "Lobby Apple TV", "_airplay._tcp", 7000},
		{"10.20.3.41", "MR1-ATV", "Meeting Room 1", "_airplay._tcp", 7000},
		{"10.20.3.52", "Chromecast-MR2", "Meeting Room 2", "_googlecast._tcp", 8009},
		{"10.20.3.53", "Chromecast-Bar", "Bar TV", "_googlecast._tcp", 8009},
		{"10.20.5.18", "NPI8A2F1C", "HP LaserJet 4th Floor", "_ipp._tcp", 631},
		{"10.20.5.19", "BRN3C2AF4", "Brother Reception", "_ipp._tcp", 631},
		{"10.20.6.30", "Sonos-B8E937", "Sonos Bar", "_sonos._tcp", 1443},
		{"10.20.6.31", "Sonos-B8E938", "Sonos Terrace", "_sonos._tcp", 1443},
		{"10.20.7.4", "ecb5fa1d", "Hue Bridge", "_hue._tcp", 443},
		{"10.20.7.9", "homeassistant", "Home", "_home-assistant._tcp", 8123},
		{"10.20.3.60", "NDI-PTZ-1", "PTZ1 (Stage)", "_ndi._tcp", 5961},
		{"10.20.2.77", "Kates-MacBook-Pro", "Kate's MacBook Pro", "_companion-link._tcp", 49152},
	}
	i := 0
	s.add(50*time.Millisecond, func(now time.Time) ([]byte, time.Duration) {
		h := hosts[i%len(hosts)]
		i++
		if i%3 == 0 { // a query for a service type
			d := newDNS(false, 1, 0)
			d.question([]string{"_airplay._tcp.local", "_googlecast._tcp.local", "_ipp._tcp.local", "_spotify-connect._tcp.local"}[i%4], 12)
			return udp(hosts[(i*5)%len(hosts)].addr, "224.0.0.251", 5353, 5353, d.b), 90 * time.Millisecond
		}
		full := h.instance + "." + h.stype + ".local"
		host := h.host + ".local"
		d := newDNS(true, 0, 3)
		d.rr(h.stype+".local", 12, func() { d.name(full) })
		d.rr(full, 33, func() {
			d.b = append(d.b, 0, 0, 0, 0)
			d.b = binary.BigEndian.AppendUint16(d.b, h.port)
			d.name(host)
		})
		d.rr(host, 1, func() { d.b = append(d.b, ip(h.addr).AsSlice()...) })
		return udp(h.addr, "224.0.0.251", 5353, 5353, d.b), 90 * time.Millisecond
	})
}

func (s *Source) llmnr() {
	names := []struct{ name, from string }{{"wpad", "10.20.2.14"}, {"FILESRV01", "10.20.2.19"}, {"wpad", "10.20.2.31"}, {"printer", "10.20.2.14"}}
	i := 0
	s.add(300*time.Millisecond, func(now time.Time) ([]byte, time.Duration) {
		n := names[i%len(names)]
		i++
		d := newDNS(false, 1, 0)
		d.question(n.name, 1)
		return udp(n.from, "224.0.0.252", 50000+uint16(i%1000), 5355, d.b), 1300 * time.Millisecond
	})
}

// ---- SSDP and WS-Discovery ----

func (s *Source) ssdp() {
	devs := []struct{ addr, server, nt, loc string }{
		{"10.20.3.61", "Linux/4.9 UPnP/1.0 Samsung TV", "urn:schemas-upnp-org:device:MediaRenderer:1", "http://10.20.3.61:9197/dmr"},
		{"10.20.1.1", "Ruckus UPnP/1.1 ICX", "urn:schemas-upnp-org:device:InternetGatewayDevice:2", "http://10.20.1.1:5000/rootDesc.xml"},
		{"10.20.5.18", "HP HTTP Server; HP LaserJet", "urn:schemas-upnp-org:device:Printer:1", "http://10.20.5.18:8080/description.xml"},
		{"10.20.6.30", "Linux UPnP/1.0 Sonos/70.3", "urn:schemas-upnp-org:device:ZonePlayer:1", "http://10.20.6.30:1400/xml/device_description.xml"},
		{"10.20.9.12", "Windows/10.0 UPnP/1.0", "urn:schemas-upnp-org:device:MediaServer:1", "http://10.20.9.12:2869/upnphost/udhisapi.dll"},
	}
	i := 0
	s.add(120*time.Millisecond, func(now time.Time) ([]byte, time.Duration) {
		i++
		if i%5 == 0 {
			msg := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n"
			return udp("10.20.2.77", "239.255.255.250", 51000, 1900, []byte(msg)), 400 * time.Millisecond
		}
		d := devs[i%len(devs)]
		msg := fmt.Sprintf("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: %s\r\nNT: %s\r\nNTS: ssdp:alive\r\nSERVER: %s\r\nUSN: uuid:%08x::%s\r\n\r\n", d.loc, d.nt, d.server, i%len(devs), d.nt)
		return udp(d.addr, "239.255.255.250", 1900, 1900, []byte(msg)), 400 * time.Millisecond
	})
}

func (s *Source) wsd() {
	msgs := []struct{ addr, action, types, xaddr string }{
		{"10.20.8.2", "Hello", "dn:NetworkVideoTransmitter tds:Device", "http://10.20.8.2/onvif/device_service"},
		{"10.20.8.3", "Hello", "dn:NetworkVideoTransmitter tds:Device", "http://10.20.8.3/onvif/device_service"},
		{"10.20.5.18", "Hello", "wprt:PrintDeviceType wscn:ScanDeviceType", "http://10.20.5.18:3911/"},
		{"10.20.2.14", "Probe", "wsdp:Device", ""},
	}
	i := 0
	s.add(700*time.Millisecond, func(now time.Time) ([]byte, time.Duration) {
		m := msgs[i%len(msgs)]
		i++
		x := ""
		if m.xaddr != "" {
			x = "<d:XAddrs>" + m.xaddr + "</d:XAddrs>"
		}
		body := fmt.Sprintf(`<?xml version="1.0"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/%s</wsa:Action></soap:Header><soap:Body><d:%s><d:Types>%s</d:Types>%s</d:%s></soap:Body></soap:Envelope>`, m.action, m.action, m.types, x, m.action)
		return udp(m.addr, "239.255.255.250", 3702, 3702, []byte(body)), 2 * time.Second
	})
}

// ---- timing and routing ----

func (s *Source) ptp() {
	gm := []byte{0x00, 0x1d, 0xc1, 0xff, 0xfe, 0x0a, 0x44, 0x12}
	hdr := func(mt uint8, l int, interval int8) []byte {
		b := make([]byte, l)
		b[0], b[1] = mt, 2
		binary.BigEndian.PutUint16(b[2:], uint16(l))
		copy(b[20:28], gm)
		b[33] = byte(interval)
		return b
	}
	s.add(10*time.Millisecond, func(now time.Time) ([]byte, time.Duration) {
		return udp("10.20.6.1", "224.0.1.129", 319, 319, hdr(0x0, 44, -3)), 125 * time.Millisecond
	})
	s.add(11*time.Millisecond, func(now time.Time) ([]byte, time.Duration) {
		return udp("10.20.6.1", "224.0.1.129", 320, 320, hdr(0x8, 44, -3)), 125 * time.Millisecond
	})
	s.add(12*time.Millisecond, func(now time.Time) ([]byte, time.Duration) {
		b := hdr(0xb, 64, 0)
		b[47], b[48], b[49] = 128, 6, 0x21
		b[52] = 128
		copy(b[53:61], gm)
		b[63] = 0x20 // GNSS
		return udp("10.20.6.1", "224.0.1.129", 320, 320, b), time.Second
	})
}

func (s *Source) igmp() {
	s.add(500*time.Millisecond, func(now time.Time) ([]byte, time.Duration) {
		q := []byte{0x11, 100, 0, 0, 0, 0, 0, 0, 0x02, 125, 0, 0}
		return raw("10.20.0.1", "224.0.0.1", pkt.ProtoIGMP, false, q), 30 * time.Second
	})
	members := []struct{ host, group string }{
		{"10.20.3.80", "239.10.1.1"}, {"10.20.3.81", "239.10.1.2"}, {"10.20.3.82", "239.10.1.3"},
		{"10.20.4.30", "239.10.2.20"}, {"10.20.6.20", "239.69.83.67"}, {"10.20.3.83", "239.10.1.7"},
	}
	i := 0
	s.add(800*time.Millisecond, func(now time.Time) ([]byte, time.Duration) {
		m := members[i%len(members)]
		i++
		r := []byte{0x22, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0}
		r = append(r, ip(m.group).AsSlice()...)
		return raw(m.host, "224.0.0.22", pkt.ProtoIGMP, false, r), 5 * time.Second
	})
}

func (s *Source) vrrp() {
	s.add(300*time.Millisecond, func(now time.Time) ([]byte, time.Duration) {
		b := []byte{0x31, 10, 120, 1, 0, 100, 0, 0, 10, 20, 0, 1}
		return raw("10.20.0.2", "224.0.0.18", pkt.ProtoVRRP, false, b), time.Second
	})
}

func (s *Source) unknown() {
	n := 0
	s.add(5*time.Millisecond, func(now time.Time) ([]byte, time.Duration) {
		n++
		msg := fmt.Sprintf(`{"type":"telemetry","seq":%d,"temp":%.1f,"fan":%d,"status":"ok","pad":"%s"}`, n, 41.5+float64(n%7)/10, 3200+n%50, strings.Repeat("x", 520))
		return udp("10.20.9.77", "239.255.0.1", 40001, 9000, []byte(msg)), 16 * time.Millisecond
	})
}

// ---- IPv6 ----

func (s *Source) ipv6() {
	router := "fe80::1e:61ff:fe00:1"
	s.add(time.Second, func(now time.Time) ([]byte, time.Duration) {
		ra := make([]byte, 16)
		ra[0] = 134
		ra[4] = 64
		ra[5] = 0x40
		binary.BigEndian.PutUint16(ra[6:], 1800)
		pfx := make([]byte, 32)
		pfx[0], pfx[1], pfx[2], pfx[3] = 3, 4, 64, 0xc0
		copy(pfx[16:], ip("2001:db8:20::").AsSlice())
		ra = append(ra, pfx...)
		return raw(router, "ff02::1", pkt.ProtoICMPv6, false, ra), 10 * time.Second
	})
	targets := []string{"fe80::a1:2", "2001:db8:20::77", "fe80::1e:61ff:fe00:1", "2001:db8:20::18", "fe80::c0:ffee"}
	i := 0
	s.add(150*time.Millisecond, func(now time.Time) ([]byte, time.Duration) {
		t := ip(targets[i%len(targets)])
		i++
		b := t.As16()
		sn := netip.AddrFrom16([16]byte{0xff, 0x02, 11: 1, 12: 0xff, 13: b[13], 14: b[14], 15: b[15]})
		ns := make([]byte, 8)
		ns[0] = 135
		ns = append(ns, t.AsSlice()...)
		src := "fe80::a1:" + fmt.Sprint(10+i%5)
		return pkt.Frame(pkt.Spec{Src: ip(src), Dst: sn, SrcMAC: mac(ip(src)), Proto: pkt.ProtoICMPv6, TTL: 255, Payload: ns}), 700 * time.Millisecond
	})
	groups := []string{"ff02::fb", "ff02::1:3", "ff02::c", "ff05::2:1"}
	j := 0
	s.add(400*time.Millisecond, func(now time.Time) ([]byte, time.Duration) {
		g := groups[j%len(groups)]
		host := "fe80::a1:" + fmt.Sprint(10+j%5)
		j++
		r := []byte{143, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0}
		r = append(r, ip(g).AsSlice()...)
		return raw(host, "ff02::16", pkt.ProtoICMPv6, true, r), 3 * time.Second
	})
	k := 0
	s.add(600*time.Millisecond, func(now time.Time) ([]byte, time.Duration) {
		k++
		d := newDNS(true, 0, 2)
		d.rr("_airplay._tcp.local", 12, func() { d.name("Lobby Apple TV._airplay._tcp.local") })
		d.rr("Lobby-ATV.local", 28, func() { d.b = append(d.b, ip("fe80::10:40").AsSlice()...) })
		return udp("fe80::10:40", "ff02::fb", 5353, 5353, d.b), 1500 * time.Millisecond
	})
}
