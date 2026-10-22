package monitor

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/andreacoppini/packhound/internal/pkt"
)

// ---- SSDP / UPnP ----

type ssdpDec struct {
	base
	notify, search window
	devices        map[string]*ssdpDevice // sender + type
	searches       map[string]*ssdpSearch // sender + search target
}

type ssdpDevice struct {
	from              netip.Addr
	server, nt, where string
	last              time.Time
}

type ssdpSearch struct {
	from  netip.Addr
	st    string
	times int
	last  time.Time
}

func newSSDP() *ssdpDec {
	return &ssdpDec{devices: map[string]*ssdpDevice{}, searches: map[string]*ssdpSearch{}}
}

func (d *ssdpDec) tick(*Stream, time.Time) { d.notify.roll(); d.search.roll() }

func (d *ssdpDec) feed(_ *Stream, p *pkt.Packet) {
	sc := bufio.NewScanner(bytes.NewReader(p.Payload))
	if !sc.Scan() {
		return
	}
	start := strings.ToUpper(sc.Text())
	h := map[string]string{}
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, ':'); i > 0 {
			h[strings.ToUpper(strings.TrimSpace(line[:i]))] = strings.TrimSpace(line[i+1:])
		}
	}
	switch {
	case strings.HasPrefix(start, "NOTIFY"):
		d.notify.add(1)
		if strings.EqualFold(h["NTS"], "ssdp:byebye") {
			delete(d.devices, p.Src.String()+h["NT"])
			return
		}
		k := p.Src.String() + h["NT"]
		dv := d.devices[k]
		if dv == nil {
			if len(d.devices) >= maxDNSEntries {
				return
			}
			dv = &ssdpDevice{from: p.Src, nt: h["NT"]}
			d.devices[k] = dv
		}
		dv.server, dv.where, dv.last = h["SERVER"], h["LOCATION"], p.Time
	case strings.HasPrefix(start, "M-SEARCH"):
		d.search.add(1)
		k := p.Src.String() + h["ST"]
		sr := d.searches[k]
		if sr == nil {
			if len(d.searches) >= maxDNSEntries {
				return
			}
			sr = &ssdpSearch{from: p.Src, st: h["ST"]}
			d.searches[k] = sr
		}
		sr.times++
		sr.last = p.Time
	}
}

// ssdpType shortens a UPnP notification type for the table.
func ssdpType(nt string) string {
	switch {
	case strings.HasPrefix(nt, "uuid:"):
		return "device UUID"
	case strings.HasPrefix(nt, "urn:schemas-upnp-org:"):
		return strings.Replace(strings.TrimPrefix(nt, "urn:schemas-upnp-org:"), ":", " ", 1)
	}
	return nt
}

func (d *ssdpDec) name(*Stream) string {
	hosts := map[netip.Addr]bool{}
	for _, dv := range d.devices {
		hosts[dv.from] = true
	}
	return fmt.Sprintf("UPnP discovery · %d devices", len(hosts))
}

func (d *ssdpDec) describe(s *Stream, det *Detail) {
	now := s.m.now
	det.add("Protocol", "SSDP (UPnP)")
	det.add("NOTIFY / M-SEARCH per second", fmt.Sprintf("%.1f / %.1f", d.notify.perSecond(10), d.search.perSecond(10)))

	// One row per device and the most specific type it announced: a
	// device repeats every NOTIFY for its UUID, root device and services.
	type row struct{ from, server, types, where string }
	byHost := map[netip.Addr]*row{}
	var order []netip.Addr
	for _, dv := range d.devices {
		r := byHost[dv.from]
		if r == nil {
			r = &row{from: dv.from.String()}
			byHost[dv.from] = r
			order = append(order, dv.from)
		}
		if r.server == "" {
			r.server = dv.server
		}
		if r.where == "" {
			r.where = dv.where
		}
		if strings.Contains(dv.nt, ":device:") {
			t := ssdpType(dv.nt)
			if !strings.Contains(r.types, t) {
				if r.types != "" {
					r.types += ", "
				}
				r.types += t
			}
		}
	}
	sort.Slice(order, func(i, j int) bool { return order[i].Less(order[j]) })
	tb := Table{Title: "Devices announced", Cols: []string{"Sender", "Server", "Device types", "Description at"}}
	for _, a := range order {
		r := byHost[a]
		tb.Rows = append(tb.Rows, []string{r.from, r.server, r.types, r.where})
	}
	det.Tables = append(det.Tables, tb)

	st := Table{Title: "Searches", Cols: []string{"Searcher", "Looking for", "Times", "Last"}}
	for _, sr := range d.searches {
		st.Rows = append(st.Rows, []string{sr.from.String(), ssdpType(sr.st), fmt.Sprint(sr.times), ago(now, sr.last)})
	}
	sort.Slice(st.Rows, func(i, j int) bool { return st.Rows[i][0] < st.Rows[j][0] })
	det.Tables = append(det.Tables, st)
}

// ---- WS-Discovery ----

type wsdDec struct {
	base
	seen map[string]*wsdEntry
}

type wsdEntry struct {
	from          netip.Addr
	action, types string
	where         string
	last          time.Time
}

var (
	wsdAction = regexp.MustCompile(`<[^>]*Action[^>]*>[^<]*/([A-Za-z]+)\s*<`)
	wsdTypes  = regexp.MustCompile(`<(?:[A-Za-z0-9]+:)?Types[^>]*>([^<]*)<`)
	wsdXAddrs = regexp.MustCompile(`<(?:[A-Za-z0-9]+:)?XAddrs[^>]*>([^<]*)<`)
)

func newWSD() *wsdDec { return &wsdDec{seen: map[string]*wsdEntry{}} }

func (d *wsdDec) feed(_ *Stream, p *pkt.Packet) {
	b := p.Payload
	act := ""
	if m := wsdAction.FindSubmatch(b); m != nil {
		act = string(m[1])
	}
	types := ""
	if m := wsdTypes.FindSubmatch(b); m != nil {
		var short []string
		for _, t := range strings.Fields(string(m[1])) {
			if i := strings.LastIndexByte(t, ':'); i >= 0 {
				t = t[i+1:]
			}
			short = append(short, t)
		}
		types = strings.Join(short, ", ")
	}
	k := p.Src.String() + act
	e := d.seen[k]
	if e == nil {
		if len(d.seen) >= maxDNSEntries {
			return
		}
		e = &wsdEntry{from: p.Src, action: act}
		d.seen[k] = e
	}
	if types != "" {
		e.types = types
	}
	if m := wsdXAddrs.FindSubmatch(b); m != nil {
		e.where = strings.Fields(string(m[1]) + " ")[0]
	}
	e.last = p.Time
}

func (d *wsdDec) name(*Stream) string {
	return "WS-Discovery (printers, cameras, Windows)"
}

func (d *wsdDec) describe(s *Stream, det *Detail) {
	det.add("Protocol", "WS-Discovery (ONVIF cameras, WSD printers, Windows network discovery)")
	tb := Table{Title: "Messages", Cols: []string{"Sender", "Message", "Types", "Address", "Last"}}
	for _, e := range d.seen {
		tb.Rows = append(tb.Rows, []string{e.from.String(), e.action, e.types, e.where, ago(s.m.now, e.last)})
	}
	sort.Slice(tb.Rows, func(i, j int) bool { return tb.Rows[i][0] < tb.Rows[j][0] })
	det.Tables = append(det.Tables, tb)
}

// ---- SAP / SDP ----

// sdpInfo is what an SDP description says about one multicast stream.
type sdpInfo struct {
	Group   netip.Addr
	Port    uint16
	Session string
	Media   string // audio, video
	Format  string // "L24/48000/2"
	PTime   string
	Origin  string
	Last    time.Time
}

type sapDec struct {
	base
	sessions map[string]*sdpInfo
}

func newSAP() *sapDec { return &sapDec{sessions: map[string]*sdpInfo{}} }

func (d *sapDec) feed(s *Stream, p *pkt.Packet) {
	b := p.Payload
	if len(b) < 8 || b[0]>>5 != 1 {
		return
	}
	deletion := b[0]&0x04 != 0
	if b[0]&0x03 != 0 { // encrypted or compressed
		return
	}
	n := 4 + 4 + int(b[1])*4 // header, IPv4 origin, auth data
	if b[0]&0x10 != 0 {
		n += 12 // IPv6 origin
	}
	if n > len(b) {
		return
	}
	b = b[n:]
	// An optional MIME type, NUL-terminated, precedes the SDP.
	if !bytes.HasPrefix(b, []byte("v=0")) {
		if i := bytes.IndexByte(b, 0); i >= 0 {
			b = b[i+1:]
		}
	}
	info, ok := parseSDP(string(b))
	if !ok {
		return
	}
	info.Last = p.Time
	id := fmt.Sprintf("%s:%d", info.Group, info.Port)
	if deletion {
		delete(d.sessions, id)
		return
	}
	if len(d.sessions) < maxDNSEntries || d.sessions[id] != nil {
		d.sessions[id] = &info
	}
	s.m.registerSDP(info)
}

func parseSDP(text string) (sdpInfo, bool) {
	var info sdpInfo
	var pt string
	rtpmap := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		v := line[2:]
		switch line[0] {
		case 's':
			info.Session = strings.TrimSpace(v)
		case 'o':
			if f := strings.Fields(v); len(f) >= 6 {
				info.Origin = f[5]
			}
		case 'c':
			// c=IN IP4 239.69.83.67/32 — media-level lines override.
			if f := strings.Fields(v); len(f) >= 3 {
				addr := strings.SplitN(f[2], "/", 2)[0]
				if a, err := netip.ParseAddr(addr); err == nil {
					info.Group = a
				}
			}
		case 'm':
			if info.Media != "" {
				continue // first media section only
			}
			if f := strings.Fields(v); len(f) >= 4 {
				info.Media = f[0]
				port, _ := strconv.Atoi(f[1])
				info.Port = uint16(port)
				pt = f[3]
			}
		case 'a':
			switch {
			case strings.HasPrefix(v, "rtpmap:"):
				if f := strings.Fields(strings.TrimPrefix(v, "rtpmap:")); len(f) == 2 {
					rtpmap[f[0]] = f[1]
				}
			case strings.HasPrefix(v, "ptime:"):
				info.PTime = strings.TrimPrefix(v, "ptime:")
			}
		}
	}
	info.Format = rtpmap[pt]
	return info, info.Group.IsValid() && info.Port != 0
}

func (d *sapDec) name(*Stream) string {
	return fmt.Sprintf("Stream announcements · %d sessions", len(d.sessions))
}

func (d *sapDec) describe(s *Stream, det *Detail) {
	det.add("Protocol", "SAP carrying SDP (AES67, Dante in AES67 mode, Livewire+, some IPTV)")
	tb := Table{Title: "Sessions announced", Cols: []string{"Session", "Group", "Media", "Format", "Packet time", "Origin", "Last"}}
	for _, i := range d.sessions {
		pt := ""
		if i.PTime != "" {
			pt = i.PTime + " ms"
		}
		tb.Rows = append(tb.Rows, []string{i.Session, fmt.Sprintf("%s:%d", i.Group, i.Port), i.Media, i.Format, pt, i.Origin, ago(s.m.now, i.Last)})
	}
	sort.Slice(tb.Rows, func(a, b int) bool { return tb.Rows[a][1] < tb.Rows[b][1] })
	det.Tables = append(det.Tables, tb)
}
