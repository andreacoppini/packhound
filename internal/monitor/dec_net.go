package monitor

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/andreacoppini/packhound/internal/pkt"
)

// ---- PTP ----

var ptpTypes = map[uint8]string{
	0x0: "Sync", 0x1: "Delay_Req", 0x2: "Pdelay_Req", 0x3: "Pdelay_Resp",
	0x8: "Follow_Up", 0x9: "Delay_Resp", 0xa: "Pdelay_Resp_Follow_Up", 0xb: "Announce",
	0xc: "Signaling", 0xd: "Management",
}

type ptpDec struct {
	base
	version  uint8
	domains  map[uint8]bool
	counts   map[uint8]*window
	clocks   map[string]netip.Addr // source clock identities and their address
	gm       string
	gmClass  uint8
	gmAcc    uint8
	gmP1     uint8
	gmP2     uint8
	steps    uint16
	source   uint8
	interval int8 // log2 seconds, from Sync
	haveSync bool
}

func newPTP() *ptpDec {
	return &ptpDec{domains: map[uint8]bool{}, counts: map[uint8]*window{}, clocks: map[string]netip.Addr{}}
}

func clockID(b []byte) string {
	return fmt.Sprintf("%02x%02x%02x.%02x%02x.%02x%02x%02x", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7])
}

func (d *ptpDec) feed(_ *Stream, p *pkt.Packet) {
	b := p.Payload
	if len(b) < 34 {
		return
	}
	d.version = b[1] & 0x0f
	if d.version != 2 {
		return
	}
	mt := b[0] & 0x0f
	d.domains[b[4]] = true
	w := d.counts[mt]
	if w == nil {
		w = &window{}
		d.counts[mt] = w
	}
	w.add(1)
	if len(d.clocks) < 64 {
		d.clocks[clockID(b[20:28])] = p.Src
	}
	switch mt {
	case 0x0:
		d.interval, d.haveSync = int8(b[33]), true
	case 0xb:
		if len(b) >= 64 {
			d.gmP1, d.gmClass, d.gmAcc = b[47], b[48], b[49]
			d.gmP2 = b[52]
			d.gm = clockID(b[53:61])
			d.steps = u16(b[61:])
			d.source = b[63]
		}
	}
}

func (d *ptpDec) tick(*Stream, time.Time) {
	for _, w := range d.counts {
		w.roll()
	}
}

func (d *ptpDec) name(*Stream) string {
	if d.version == 1 {
		return "PTPv1"
	}
	doms := d.domainList()
	n := "Precision Time Protocol, domain " + doms
	if d.gm != "" {
		n += " · grandmaster " + d.gm
	}
	return n
}

func (d *ptpDec) domainList() string {
	var ds []string
	for k := range d.domains {
		ds = append(ds, fmt.Sprint(k))
	}
	sort.Strings(ds)
	return strings.Join(ds, ", ")
}

var ptpSources = map[uint8]string{0x10: "atomic clock", 0x20: "GNSS", 0x30: "terrestrial radio", 0x40: "PTP", 0x50: "NTP", 0x60: "hand set", 0x90: "other", 0xa0: "internal oscillator"}

func (d *ptpDec) describe(s *Stream, det *Detail) {
	det.add("Protocol", fmt.Sprintf("IEEE 1588 PTPv%d", d.version))
	det.add("Domain", d.domainList())
	if d.gm != "" {
		det.add("Grandmaster", d.gm)
		det.add("Clock class / accuracy", fmt.Sprintf("%d / 0x%02x", d.gmClass, d.gmAcc))
		det.add("Priority 1 / 2", fmt.Sprintf("%d / %d", d.gmP1, d.gmP2))
		det.add("Steps removed", fmt.Sprint(d.steps))
		if src, ok := ptpSources[d.source]; ok {
			det.add("Time source", src)
		}
	}
	if d.haveSync {
		det.add("Sync interval", fmt.Sprintf("%g ms", 1000*pow2(d.interval)))
	}
	tb := Table{Title: "Messages", Cols: []string{"Message", "Per second"}}
	var mts []int
	for k := range d.counts {
		mts = append(mts, int(k))
	}
	sort.Ints(mts)
	for _, k := range mts {
		name := ptpTypes[uint8(k)]
		if name == "" {
			name = fmt.Sprintf("type %d", k)
		}
		tb.Rows = append(tb.Rows, []string{name, fmt.Sprintf("%.1f", d.counts[uint8(k)].perSecond(10))})
	}
	det.Tables = append(det.Tables, tb)
	ct := Table{Title: "Clocks heard", Cols: []string{"Clock identity", "Address"}}
	for id, a := range d.clocks {
		ct.Rows = append(ct.Rows, []string{id, a.String()})
	}
	sort.Slice(ct.Rows, func(i, j int) bool { return ct.Rows[i][0] < ct.Rows[j][0] })
	det.Tables = append(det.Tables, ct)
}

func pow2(n int8) float64 {
	v := 1.0
	for ; n > 0; n-- {
		v *= 2
	}
	for ; n < 0; n++ {
		v /= 2
	}
	return v
}

// ---- IGMP ----

type igmpDec struct {
	base
	queriers map[netip.Addr]*querier
	members  map[string]*membership
}

type querier struct {
	addr     netip.Addr
	version  int
	interval time.Duration // as advertised (v3) or as measured
	last     time.Time
	general  int
	specific int
	lastGen  time.Time
}

type membership struct {
	host   netip.Addr
	group  string
	record string
	last   time.Time
}

func (d *igmpDec) feed(_ *Stream, p *pkt.Packet) {
	b := p.Payload
	if len(b) < 8 {
		return
	}
	if d.queriers == nil {
		d.queriers, d.members = map[netip.Addr]*querier{}, map[string]*membership{}
	}
	group := netip.AddrFrom4([4]byte(b[4:8]))
	switch b[0] {
	case 0x11:
		q := d.queriers[p.Src]
		if q == nil {
			q = &querier{addr: p.Src}
			d.queriers[p.Src] = q
		}
		switch {
		case len(b) >= 12:
			q.version = 3
			if qqic := b[9]; qqic > 0 {
				q.interval = time.Duration(igmpCode(qqic)) * time.Second
			}
		case b[1] == 0:
			q.version = 1
		default:
			q.version = 2
		}
		if group.IsUnspecified() {
			if !q.lastGen.IsZero() && q.version != 3 {
				q.interval = p.Time.Sub(q.lastGen).Round(time.Second)
			}
			q.lastGen = p.Time
			q.general++
		} else {
			q.specific++
		}
		q.last = p.Time
	case 0x12, 0x16:
		d.member(p.Src, group.String(), map[byte]string{0x12: "v1 report", 0x16: "v2 report"}[b[0]], p.Time)
	case 0x17:
		d.member(p.Src, group.String(), "v2 leave", p.Time)
	case 0x22:
		n := int(u16(b[6:]))
		off := 8
		for i := 0; i < n && off+8 <= len(b); i++ {
			rt, aux, ns := b[off], int(b[off+1]), int(u16(b[off+2:]))
			g := netip.AddrFrom4([4]byte(b[off+4 : off+8]))
			d.member(p.Src, g.String(), igmpRecord(rt, ns), p.Time)
			off += 8 + 4*ns + 4*aux
		}
	}
}

// igmpCode decodes IGMPv3's floating-point time codes.
func igmpCode(c byte) int {
	if c < 128 {
		return int(c)
	}
	return int(c&0x0f|0x10) << (int(c>>4&0x07) + 3)
}

func igmpRecord(t byte, sources int) string {
	switch t {
	case 1, 3:
		if sources == 0 {
			if t == 3 {
				return "v3 leave"
			}
			return "v3 member (no sources)"
		}
		return fmt.Sprintf("v3 member, %d sources", sources)
	case 2, 4:
		if sources == 0 {
			return "v3 join (any source)"
		}
		return fmt.Sprintf("v3 join, excluding %d sources", sources)
	case 5:
		return fmt.Sprintf("v3 allow %d sources", sources)
	case 6:
		return fmt.Sprintf("v3 block %d sources", sources)
	}
	return fmt.Sprintf("v3 record type %d", t)
}

func (d *igmpDec) member(host netip.Addr, group, rec string, t time.Time) {
	k := host.String() + " " + group
	m := d.members[k]
	if m == nil {
		if len(d.members) >= maxDNSEntries {
			return
		}
		m = &membership{host: host, group: group}
		d.members[k] = m
	}
	m.record, m.last = rec, t
}

// elected is the querier that wins: the lowest address heard recently.
func (d *igmpDec) elected(now time.Time) *querier {
	var best *querier
	for _, q := range d.queriers {
		if now.Sub(q.last) > 5*time.Minute {
			continue
		}
		if best == nil || q.addr.Less(best.addr) {
			best = q
		}
	}
	return best
}

func (d *igmpDec) name(s *Stream) string {
	if q := d.elected(s.m.now); q != nil {
		return fmt.Sprintf("IGMPv%d queries · querier %s", q.version, q.addr)
	}
	switch s.key.Dst.String() {
	case "224.0.0.22":
		return fmt.Sprintf("IGMPv3 membership reports · %d entries", len(d.members))
	case "224.0.0.2":
		return "IGMPv2 leaves"
	}
	return "IGMP reports for this group"
}

func (d *igmpDec) describe(s *Stream, det *Detail) {
	now := s.m.now
	if q := d.elected(now); q != nil {
		det.add("Elected querier", q.addr.String())
		if len(d.queriers) > 1 {
			det.add("Queriers heard", fmt.Sprint(len(d.queriers)))
		}
	}
	if len(d.queriers) > 0 {
		tb := Table{Title: "Queriers", Cols: []string{"Querier", "Version", "Interval", "General / group queries", "Last"}}
		for _, q := range d.queriers {
			iv := "-"
			if q.interval > 0 {
				iv = q.interval.String()
			}
			tb.Rows = append(tb.Rows, []string{q.addr.String(), fmt.Sprintf("v%d", q.version), iv, fmt.Sprintf("%d / %d", q.general, q.specific), ago(now, q.last)})
		}
		sort.Slice(tb.Rows, func(i, j int) bool { return tb.Rows[i][0] < tb.Rows[j][0] })
		det.Tables = append(det.Tables, tb)
	}
	if len(d.members) > 0 {
		tb := Table{Title: "Membership reports", Cols: []string{"Host", "Group", "Report", "Last"}}
		for _, m := range d.members {
			tb.Rows = append(tb.Rows, []string{m.host.String(), m.group, m.record, ago(now, m.last)})
		}
		sort.Slice(tb.Rows, func(i, j int) bool {
			if tb.Rows[i][1] != tb.Rows[j][1] {
				return tb.Rows[i][1] < tb.Rows[j][1]
			}
			return tb.Rows[i][0] < tb.Rows[j][0]
		})
		det.Tables = append(det.Tables, tb)
	}
}

// ---- VRRP and HSRP ----

// gwDec reads first-hop redundancy hellos. Only the active router speaks in
// VRRP, so more than one speaker for the same group means a split brain.
type gwDec struct {
	base
	hsrp    bool
	routers map[string]*gwRouter
}

type gwRouter struct {
	addr     netip.Addr
	group    int
	priority int
	state    string
	interval string
	vips     string
	last     time.Time
}

func newHSRP() *gwDec { return &gwDec{hsrp: true} }

type vrrpDec = gwDec

func (d *gwDec) feed(_ *Stream, p *pkt.Packet) {
	b := p.Payload
	if d.routers == nil {
		d.routers = map[string]*gwRouter{}
	}
	r := &gwRouter{addr: p.Src, last: p.Time}
	if d.hsrp {
		if len(b) < 20 || b[0] != 0 {
			return // HSRPv2 uses TLVs; only v1 is read
		}
		r.state = map[byte]string{0: "Initial", 1: "Learn", 2: "Listen", 4: "Speak", 8: "Standby", 16: "Active"}[b[2]]
		r.interval = fmt.Sprintf("%d s", b[3])
		r.priority, r.group = int(b[5]), int(b[6])
		r.vips = netip.AddrFrom4([4]byte(b[16:20])).String()
	} else {
		if len(b) < 8 {
			return
		}
		ver := b[0] >> 4
		r.group, r.priority = int(b[1]), int(b[2])
		n := int(b[3])
		r.state = "Master"
		var vips []string
		alen := 4
		if p.IsV6() {
			alen = 16
		}
		if ver == 2 {
			r.interval = fmt.Sprintf("%d s", b[5])
		} else {
			r.interval = fmt.Sprintf("%d ms", 10*(int(b[4]&0x0f)<<8|int(b[5])))
		}
		for i, off := 0, 8; i < n && off+alen <= len(b); i, off = i+1, off+alen {
			a, _ := netip.AddrFromSlice(b[off : off+alen])
			vips = append(vips, a.String())
		}
		r.vips = strings.Join(vips, ", ")
	}
	k := fmt.Sprintf("%s/%d", p.Src, r.group)
	if len(d.routers) < 256 || d.routers[k] != nil {
		d.routers[k] = r
	}
}

func (d *gwDec) active(now time.Time) []*gwRouter {
	var out []*gwRouter
	for _, r := range d.routers {
		if now.Sub(r.last) < 10*time.Second && (!d.hsrp || r.state == "Active") {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].group < out[j].group })
	return out
}

func (d *gwDec) name(s *Stream) string {
	proto := "VRRP"
	if d.hsrp {
		proto = "HSRP"
	}
	act := d.active(s.m.now)
	if len(act) == 0 {
		return proto + " gateway redundancy"
	}
	r := act[0]
	n := fmt.Sprintf("%s group %d · active %s (priority %d)", proto, r.group, r.addr, r.priority)
	if len(act) > 1 {
		n += fmt.Sprintf(" · %d groups", len(act))
	}
	return n
}

func (d *gwDec) describe(s *Stream, det *Detail) {
	now := s.m.now
	if !d.hsrp {
		det.add("Note", "only the master advertises; two advertisers for one group is a split brain")
		groups := map[int]int{}
		for _, r := range d.active(now) {
			groups[r.group]++
		}
		for g, n := range groups {
			if n > 1 {
				det.add("Split brain", fmt.Sprintf("group %d has %d routers advertising", g, n))
			}
		}
	}
	tb := Table{Title: "Routers", Cols: []string{"Router", "Group", "Priority", "State", "Interval", "Virtual addresses", "Last"}}
	for _, r := range d.routers {
		tb.Rows = append(tb.Rows, []string{r.addr.String(), fmt.Sprint(r.group), fmt.Sprint(r.priority), r.state, r.interval, r.vips, ago(now, r.last)})
	}
	sort.Slice(tb.Rows, func(i, j int) bool { return tb.Rows[i][1]+tb.Rows[i][0] < tb.Rows[j][1]+tb.Rows[j][0] })
	det.Tables = append(det.Tables, tb)
}

// ---- ICMPv6: neighbour discovery and MLD ----

var icmp6Types = map[uint8]string{
	130: "MLD query", 131: "MLDv1 report", 132: "MLDv1 done", 143: "MLDv2 report",
	133: "Router solicitation", 134: "Router advertisement", 135: "Neighbour solicitation",
	136: "Neighbour advertisement", 137: "Redirect",
}

type icmp6Dec struct {
	base
	group   string
	counts  map[uint8]*window
	routers map[netip.Addr]*raInfo
	members map[string]*membership
	targets map[netip.Addr]*askedName
}

type raInfo struct {
	lifetime int
	flags    string
	prefixes []string
	dns      []string
	last     time.Time
}

func newICMP6(k Key) *icmp6Dec {
	return &icmp6Dec{group: k.Dst.String(), counts: map[uint8]*window{}, routers: map[netip.Addr]*raInfo{},
		members: map[string]*membership{}, targets: map[netip.Addr]*askedName{}}
}

func (d *icmp6Dec) feed(_ *Stream, p *pkt.Packet) {
	b := p.Payload
	if len(b) < 4 {
		return
	}
	t := b[0]
	w := d.counts[t]
	if w == nil {
		w = &window{}
		d.counts[t] = w
	}
	w.add(1)
	switch t {
	case 134:
		if len(b) < 16 {
			return
		}
		ra := &raInfo{lifetime: int(u16(b[6:])), last: p.Time}
		if b[5]&0x80 != 0 {
			ra.flags += "M"
		}
		if b[5]&0x40 != 0 {
			ra.flags += "O"
		}
		for opt := b[16:]; len(opt) >= 8; {
			l := int(opt[1]) * 8
			if l == 0 || l > len(opt) {
				break
			}
			switch opt[0] {
			case 3: // prefix information
				if l >= 32 {
					pfx, _ := netip.AddrFromSlice(opt[16:32])
					ra.prefixes = append(ra.prefixes, fmt.Sprintf("%s/%d", pfx, opt[2]))
				}
			case 25: // recursive DNS servers
				for o := 8; o+16 <= l; o += 16 {
					a, _ := netip.AddrFromSlice(opt[o : o+16])
					ra.dns = append(ra.dns, a.String())
				}
			}
			opt = opt[l:]
		}
		if len(d.routers) < 64 || d.routers[p.Src] != nil {
			d.routers[p.Src] = ra
		}
	case 135:
		if len(b) >= 24 && len(d.targets) < maxDNSEntries {
			tgt, _ := netip.AddrFromSlice(b[8:24])
			a := d.targets[tgt]
			if a == nil {
				a = &askedName{name: tgt.String()}
				d.targets[tgt] = a
			}
			a.by, a.last = p.Src, p.Time
			a.times++
		}
	case 131, 132:
		if len(b) >= 24 {
			g, _ := netip.AddrFromSlice(b[8:24])
			d.member(p.Src, g.String(), icmp6Types[t], p.Time)
		}
	case 143:
		n := int(u16(b[6:]))
		off := 8
		for i := 0; i < n && off+20 <= len(b); i++ {
			rt, aux, ns := b[off], int(b[off+1]), int(u16(b[off+2:]))
			g, _ := netip.AddrFromSlice(b[off+4 : off+20])
			d.member(p.Src, g.String(), strings.Replace(igmpRecord(rt, ns), "v3", "MLDv2", 1), p.Time)
			off += 20 + 16*ns + 4*aux
		}
	}
}

func (d *icmp6Dec) member(host netip.Addr, group, rec string, t time.Time) {
	k := host.String() + " " + group
	m := d.members[k]
	if m == nil {
		if len(d.members) >= maxDNSEntries {
			return
		}
		m = &membership{host: host, group: group}
		d.members[k] = m
	}
	m.record, m.last = rec, t
}

func (d *icmp6Dec) tick(*Stream, time.Time) {
	for _, w := range d.counts {
		w.roll()
	}
}

func (d *icmp6Dec) name(s *Stream) string {
	switch {
	case s.key.Dst == solicitedNode.Addr():
		return fmt.Sprintf("Neighbour solicitations · %d addresses", len(d.targets))
	case d.group == "ff02::1":
		if len(d.routers) > 0 {
			return fmt.Sprintf("All nodes · %d routers advertising", len(d.routers))
		}
		return "All nodes (router adverts, MLD queries)"
	case d.group == "ff02::2":
		return "All routers (router solicitations)"
	case d.group == "ff02::16":
		return fmt.Sprintf("MLDv2 reports · %d entries", len(d.members))
	}
	var parts []string
	for t := range d.counts {
		if n, ok := icmp6Types[t]; ok {
			parts = append(parts, n)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func (d *icmp6Dec) describe(s *Stream, det *Detail) {
	now := s.m.now
	tb := Table{Title: "Messages", Cols: []string{"Message", "Per second", "Last minute"}}
	var ts []int
	for t := range d.counts {
		ts = append(ts, int(t))
	}
	sort.Ints(ts)
	for _, t := range ts {
		name := icmp6Types[uint8(t)]
		if name == "" {
			name = fmt.Sprintf("type %d", t)
		}
		w := d.counts[uint8(t)]
		tb.Rows = append(tb.Rows, []string{name, fmt.Sprintf("%.1f", w.perSecond(10)), fmt.Sprint(w.minute())})
	}
	det.Tables = append(det.Tables, tb)
	if len(d.routers) > 0 {
		rt := Table{Title: "Routers advertising", Cols: []string{"Router", "Lifetime", "Flags", "Prefixes", "DNS", "Last"}}
		for a, r := range d.routers {
			rt.Rows = append(rt.Rows, []string{a.String(), fmt.Sprintf("%d s", r.lifetime), r.flags, strings.Join(r.prefixes, ", "), strings.Join(r.dns, ", "), ago(now, r.last)})
		}
		det.Tables = append(det.Tables, rt)
	}
	if len(d.members) > 0 {
		mt := Table{Title: "Membership reports", Cols: []string{"Host", "Group", "Report", "Last"}}
		for _, m := range d.members {
			mt.Rows = append(mt.Rows, []string{m.host.String(), m.group, m.record, ago(now, m.last)})
		}
		sort.Slice(mt.Rows, func(i, j int) bool { return mt.Rows[i][1]+mt.Rows[i][0] < mt.Rows[j][1]+mt.Rows[j][0] })
		det.Tables = append(det.Tables, mt)
	}
	if len(d.targets) > 0 {
		list := make([]*askedName, 0, len(d.targets))
		for _, a := range d.targets {
			list = append(list, a)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].times > list[j].times })
		if len(list) > 100 {
			list = list[:100]
		}
		nt := Table{Title: "Addresses being resolved", Cols: []string{"Target", "Last asked by", "Times", "Last"}}
		for _, a := range list {
			nt.Rows = append(nt.Rows, []string{a.name, a.by.String(), fmt.Sprint(a.times), ago(now, a.last)})
		}
		det.Tables = append(det.Tables, nt)
	}
}
