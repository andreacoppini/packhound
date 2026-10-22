package monitor

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/andreacoppini/packhound/internal/pkt"
)

// dnsDec reads multicast DNS (Bonjour) and LLMNR, which share the DNS message
// format: mDNS to list the services devices announce, LLMNR to list the names
// Windows machines are asking for.
type dnsDec struct {
	base
	mdns      bool
	queries   window
	responses window
	services  map[string]*mdnsService // by full instance name
	hosts     map[string][]netip.Addr // by host name
	asked     map[string]*askedName
}

type mdnsService struct {
	instance, stype, host string
	port                  uint16
	last                  time.Time
}

type askedName struct {
	name  string
	by    netip.Addr
	times int
	last  time.Time
}

const maxDNSEntries = 1000

func newDNS(mdns bool) *dnsDec {
	return &dnsDec{mdns: mdns, services: map[string]*mdnsService{}, hosts: map[string][]netip.Addr{}, asked: map[string]*askedName{}}
}

func (d *dnsDec) tick(*Stream, time.Time) {
	d.queries.roll()
	d.responses.roll()
}

func (d *dnsDec) feed(_ *Stream, p *pkt.Packet) {
	msg, ok := parseDNS(p.Payload)
	if !ok {
		return
	}
	if !msg.response {
		d.queries.add(1)
		for _, q := range msg.questions {
			a := d.asked[strings.ToLower(q)]
			if a == nil {
				if len(d.asked) >= maxDNSEntries {
					continue
				}
				a = &askedName{name: q}
				d.asked[strings.ToLower(q)] = a
			}
			a.by, a.last = p.Src, p.Time
			a.times++
		}
		return
	}
	d.responses.add(1)
	for _, rr := range msg.records {
		switch rr.typ {
		case 12: // PTR: service type -> instance
			if strings.HasPrefix(rr.name, "_services._dns-sd.") || strings.HasSuffix(rr.name, ".arpa") {
				continue
			}
			sv := d.service(rr.target, p.Time)
			if sv != nil && sv.stype == "" {
				sv.stype = strings.TrimSuffix(rr.name, ".local")
			}
		case 33: // SRV: instance -> host and port
			if sv := d.service(rr.name, p.Time); sv != nil {
				sv.host, sv.port = rr.target, rr.port
			}
		case 1, 28: // A, AAAA
			if len(d.hosts) >= maxDNSEntries {
				continue
			}
			list := d.hosts[rr.name]
			found := false
			for _, a := range list {
				if a == rr.addr {
					found = true
				}
			}
			if !found && len(list) < 8 {
				d.hosts[rr.name] = append(list, rr.addr)
			}
		}
	}
}

func (d *dnsDec) service(full string, t time.Time) *mdnsService {
	sv := d.services[full]
	if sv == nil {
		if len(d.services) >= maxDNSEntries {
			return nil
		}
		sv = &mdnsService{}
		// "Lobby TV._airplay._tcp.local": the instance is everything before
		// the first label that starts with an underscore.
		parts := strings.Split(full, "._")
		sv.instance = parts[0]
		if len(parts) > 1 {
			sv.stype = "_" + strings.TrimSuffix(strings.Join(parts[1:], "._"), ".local")
		}
		d.services[full] = sv
	}
	sv.last = t
	return sv
}

func (d *dnsDec) name(*Stream) string {
	if d.mdns {
		if len(d.services) == 0 {
			return "Bonjour / mDNS"
		}
		types := map[string]bool{}
		for _, s := range d.services {
			types[s.stype] = true
		}
		return fmt.Sprintf("Bonjour / mDNS · %d services, %d types", len(d.services), len(types))
	}
	return fmt.Sprintf("Windows name lookups · %d names", len(d.asked))
}

func (d *dnsDec) describe(s *Stream, det *Detail) {
	now := s.m.now
	if d.mdns {
		det.add("Protocol", "Multicast DNS (RFC 6762)")
	} else {
		det.add("Protocol", "LLMNR (RFC 4795)")
	}
	det.add("Queries / responses per second", fmt.Sprintf("%.1f / %.1f", d.queries.perSecond(10), d.responses.perSecond(10)))

	if d.mdns {
		list := make([]*mdnsService, 0, len(d.services))
		for _, sv := range d.services {
			list = append(list, sv)
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].stype != list[j].stype {
				return list[i].stype < list[j].stype
			}
			return list[i].instance < list[j].instance
		})
		tb := Table{Title: "Services announced", Cols: []string{"Instance", "Service", "Host", "Address", "Port", "Last heard"}}
		for _, sv := range list {
			addr := ""
			if a := d.hosts[sv.host]; len(a) > 0 {
				addr = a[0].String()
			}
			port := ""
			if sv.port != 0 {
				port = fmt.Sprint(sv.port)
			}
			tb.Rows = append(tb.Rows, []string{sv.instance, serviceLabel(sv.stype), strings.TrimSuffix(sv.host, "."), addr, port, ago(now, sv.last)})
		}
		det.Tables = append(det.Tables, tb)
	}

	asked := make([]*askedName, 0, len(d.asked))
	for _, a := range d.asked {
		asked = append(asked, a)
	}
	sort.Slice(asked, func(i, j int) bool { return asked[i].times > asked[j].times })
	if len(asked) > 100 {
		asked = asked[:100]
	}
	tb := Table{Title: "Names asked for", Cols: []string{"Name", "Last asked by", "Times", "Last asked"}}
	for _, a := range asked {
		tb.Rows = append(tb.Rows, []string{a.name, a.by.String(), fmt.Sprint(a.times), ago(now, a.last)})
	}
	det.Tables = append(det.Tables, tb)
}

// serviceLabel names the DNS-SD service types people meet on real networks.
func serviceLabel(t string) string {
	known := map[string]string{
		"_airplay._tcp": "AirPlay", "_raop._tcp": "AirPlay audio", "_googlecast._tcp": "Chromecast",
		"_ipp._tcp": "Printer (IPP)", "_ipps._tcp": "Printer (IPPS)", "_printer._tcp": "Printer (LPD)",
		"_pdl-datastream._tcp": "Printer (raw)", "_scanner._tcp": "Scanner", "_uscan._tcp": "Scanner (eSCL)",
		"_hap._tcp": "HomeKit", "_hap._udp": "HomeKit (Thread)", "_hue._tcp": "Philips Hue", "_sonos._tcp": "Sonos",
		"_spotify-connect._tcp": "Spotify Connect", "_smb._tcp": "File share (SMB)", "_afpovertcp._tcp": "File share (AFP)",
		"_companion-link._tcp": "Apple device", "_sleep-proxy._udp": "Bonjour sleep proxy", "_matter._tcp": "Matter",
		"_matterc._udp": "Matter (commissioning)", "_ndi._tcp": "NDI source", "_ssh._tcp": "SSH", "_sftp-ssh._tcp": "SFTP",
		"_http._tcp": "Web page", "_https._tcp": "Web page (HTTPS)", "_meshcop._udp": "Thread border router",
		"_airport._tcp": "AirPort", "_amzn-wplay._tcp": "Fire TV", "_device-info._tcp": "Device info",
		"_rdlink._tcp": "Apple remote", "_touch-able._tcp": "Apple remote", "_daap._tcp": "iTunes sharing",
		"_workstation._tcp": "Workstation", "_rfb._tcp": "Screen sharing (VNC)", "_adisk._tcp": "Time Machine",
		"_nvstream._tcp": "NVIDIA streaming", "_esphomelib._tcp": "ESPHome", "_home-assistant._tcp": "Home Assistant",
	}
	if l, ok := known[t]; ok {
		return l + " (" + t + ")"
	}
	return t
}

// ---- a minimal DNS message reader ----

type dnsMsg struct {
	response  bool
	questions []string
	records   []dnsRR
}

type dnsRR struct {
	name   string
	typ    uint16
	target string // PTR target, SRV target
	port   uint16
	addr   netip.Addr
}

func parseDNS(b []byte) (dnsMsg, bool) {
	var m dnsMsg
	if len(b) < 12 {
		return m, false
	}
	m.response = b[2]&0x80 != 0
	qd, an, ns, ar := int(u16(b[4:])), int(u16(b[6:])), int(u16(b[8:])), int(u16(b[10:]))
	off := 12
	for i := 0; i < qd; i++ {
		name, n, ok := dnsName(b, off)
		if !ok || n+4 > len(b) {
			return m, false
		}
		m.questions = append(m.questions, name)
		off = n + 4
	}
	for i := 0; i < an+ns+ar; i++ {
		name, n, ok := dnsName(b, off)
		if !ok || n+10 > len(b) {
			return m, i > 0 || qd > 0
		}
		typ := u16(b[n:])
		rdl := int(u16(b[n+8:]))
		rd := n + 10
		if rd+rdl > len(b) {
			return m, true
		}
		rr := dnsRR{name: name, typ: typ}
		switch typ {
		case 1:
			if rdl == 4 {
				rr.addr = netip.AddrFrom4([4]byte(b[rd : rd+4]))
			}
		case 28:
			if rdl == 16 {
				rr.addr = netip.AddrFrom16([16]byte(b[rd : rd+16]))
			}
		case 12:
			rr.target, _, _ = dnsName(b, rd)
		case 33:
			if rdl >= 7 {
				rr.port = u16(b[rd+4:])
				rr.target, _, _ = dnsName(b, rd+6)
			}
		}
		m.records = append(m.records, rr)
		off = rd + rdl
	}
	return m, true
}

// dnsName reads a possibly compressed name at off, returning it and the
// offset just past it in the original position.
func dnsName(b []byte, off int) (string, int, bool) {
	var labels []string
	end := -1
	for jumps := 0; jumps < 32; {
		if off >= len(b) {
			return "", 0, false
		}
		l := int(b[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end, true
		case l&0xc0 == 0xc0:
			if off+1 >= len(b) {
				return "", 0, false
			}
			if end < 0 {
				end = off + 2
			}
			off = int(u16(b[off:]) & 0x3fff)
			jumps++
		default:
			if off+1+l > len(b) {
				return "", 0, false
			}
			labels = append(labels, string(b[off+1:off+1+l]))
			off += 1 + l
		}
	}
	return "", 0, false
}
