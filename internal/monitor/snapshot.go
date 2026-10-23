package monitor

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"time"

	"github.com/andreacoppini/packhound/internal/pkt"
)

// Row is one stream as the table shows it.
type Row struct {
	Key      string  `json:"key"`
	Family   int     `json:"family"` // 4 or 6
	Group    string  `json:"group"`
	Addr     string  `json:"addr"`
	Port     int     `json:"port"`
	Proto    string  `json:"proto"`
	Kind     Kind    `json:"kind"`
	Type     string  `json:"type"`
	Name     string  `json:"name"`
	Sender   string  `json:"sender"`
	Senders  int     `json:"senders"`
	BPS      float64 `json:"bps"`
	PPS      float64 `json:"pps"`
	AvgSize  int     `json:"avgSize"`
	JitterMs float64 `json:"jitterMs"` // -1 when not meaningful
	Errors   string  `json:"errors"`
	ErrLevel string  `json:"errLevel"`
	// Continuity errors in the last minute that the sender made: in the
	// stream as sent, nothing lost on the network.
	SourceErrors uint64 `json:"sourceErrors,omitempty"`
	// ErrorsLastMinute is the number behind Errors: loss in the last minute.
	ErrorsLastMinute uint64 `json:"errorsLastMinute"`
	// SenderName is what the single sender calls itself over mDNS, if it does.
	SenderName string `json:"senderName,omitempty"`
	// PlayURL opens the stream in a player such as VLC, for streams one can
	// play: MPEG-TS over UDP or RTP.
	PlayURL     string    `json:"playURL,omitempty"`
	Status      Status    `json:"status"`
	StatusLevel string    `json:"statusLevel"`
	Reason      string    `json:"reason,omitempty"`
	Spark       []float64 `json:"spark"`
	FirstSeen   time.Time `json:"firstSeen"`
	LastSeen    time.Time `json:"lastSeen"`
	Packets     uint64    `json:"packets"`
	Bytes       uint64    `json:"bytes"`
	VLAN        uint16    `json:"vlan,omitempty"`
}

// StreamDetail is the detail panel for one stream.
type StreamDetail struct {
	Row
	Detail
	Series  []float64 `json:"series"` // bit rate, oldest first
	Step    int       `json:"step"`   // seconds per point
	Senders Table     `json:"senders"`
}

// Totals are the header counters.
type Totals struct {
	Streams  int     `json:"streams"`
	V4       int     `json:"v4"`
	V6       int     `json:"v6"`
	Senders  int     `json:"senders"`
	BPS      float64 `json:"bps"`
	PPS      float64 `json:"pps"`
	Problems int     `json:"problems"` // streams Lost or Degraded now
	Dropped  uint64  `json:"dropped,omitempty"`
	// Packets this machine lost before reading them: in total, and in the
	// last minute.
	LocalDrops    uint64 `json:"localDrops"`
	LocalDropsMin uint64 `json:"localDropsMin"`
}

// Snapshot is everything the console needs for one refresh.
type Snapshot struct {
	Now     time.Time     `json:"now"`
	Started time.Time     `json:"started"`
	Totals  Totals        `json:"totals"`
	Rows    []Row         `json:"rows"`
	Detail  *StreamDetail `json:"detail,omitempty"`
	Alerts  []Alert       `json:"alerts"`
	Log     []LogLine     `json:"log"`
}

var protoNames = map[uint8]string{
	pkt.ProtoIGMP: "IGMP", pkt.ProtoUDP: "UDP", pkt.ProtoICMPv6: "ICMPv6", pkt.ProtoOSPF: "OSPF",
	pkt.ProtoPIM: "PIM", pkt.ProtoVRRP: "VRRP", pkt.ProtoEIGRP: "EIGRP",
}

// Snapshot reports every stream, plus the detail of the one keyed sel over
// the last window seconds.
func (m *Monitor) Snapshot(sel string, window int) Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	snap := Snapshot{Now: m.now, Started: m.started, Rows: make([]Row, 0, len(m.streams))}
	senders := map[string]bool{}
	for _, s := range m.streams {
		r := s.row()
		snap.Rows = append(snap.Rows, r)
		snap.Totals.Streams++
		if r.Family == 6 {
			snap.Totals.V6++
		} else {
			snap.Totals.V4++
		}
		snap.Totals.BPS += r.BPS
		snap.Totals.PPS += r.PPS
		if s.status == Lost || s.status == Degraded {
			snap.Totals.Problems++
		}
		for a := range s.senders {
			senders[a.String()] = true
		}
		if r.Key == sel {
			snap.Detail = s.detail(r, window)
		}
	}
	snap.Totals.Senders = len(senders)
	snap.Totals.Dropped = m.dropped
	snap.Totals.LocalDrops = m.localDrops
	snap.Totals.LocalDropsMin = m.localWin.minute()
	sort.Slice(snap.Rows, func(i, j int) bool {
		if snap.Rows[i].BPS != snap.Rows[j].BPS {
			return snap.Rows[i].BPS > snap.Rows[j].BPS
		}
		return snap.Rows[i].Key < snap.Rows[j].Key
	})
	// Empty lists, not nil: they are JSON for the console, which reads them
	// as arrays.
	snap.Alerts = append([]Alert{}, m.alerts...)
	snap.Log = append([]LogLine{}, m.log...)
	return snap
}

func (s *Stream) row() Row {
	cfg := s.m.cfg
	n := cfg.AvgSeconds
	r := Row{
		Key:         s.key.String(),
		Family:      4,
		Group:       s.groupLabel(),
		Addr:        s.key.Dst.String(),
		Port:        int(s.key.Port),
		Proto:       protoNames[s.key.Proto],
		Kind:        s.kind,
		Type:        s.typ,
		Name:        s.name(),
		Senders:     len(s.senders),
		BPS:         s.rateOver(n),
		PPS:         s.ppsOver(n),
		JitterMs:    -1,
		Status:      s.status,
		StatusLevel: s.status.level(),
		Reason:      s.reason,
		FirstSeen:   s.first,
		LastSeen:    s.last,
		Packets:     s.pkts,
		Bytes:       s.bytes,
		VLAN:        s.vlan,
	}
	if s.key.Dst.Is6() {
		r.Family = 6
	}
	if r.Proto == "" {
		r.Proto = fmt.Sprintf("IP %d", s.key.Proto)
	}
	r.PlayURL = s.playURL()
	r.SenderName = s.deviceName()
	if s.key.Dst == solicitedNode.Addr() {
		r.Addr = solicitedNode.String()
	}
	if s.pkts > 0 {
		r.AvgSize = int(s.bytes / s.pkts)
	}
	switch len(s.senders) {
	case 1:
		for a := range s.senders {
			r.Sender = a.String()
		}
	default:
		r.Sender = fmt.Sprintf("%d senders", len(s.senders))
	}
	// Jitter only means something for traffic that is meant to be steady.
	if s.kind.media() {
		if s.status != Lost && s.meanIAT > 0 {
			r.JitterMs = s.devIAT * 1000
		}
	}
	r.Errors, r.ErrLevel = "-", "ok"
	if s.dec != nil {
		if errs, label := s.dec.errorsLastMinute(); label != "" {
			r.Errors = "0"
			r.ErrorsLastMinute = errs
			if errs > 0 {
				r.Errors = fmt.Sprintf("%d /min", errs)
				r.ErrLevel = "err"
			}
		}
	}
	// Errors the sender made are shown, but apart: they are in the stream as
	// sent, not lost on the network, and do not make it Degraded.
	if se, ok := s.dec.(interface{ sourceErrorsLastMinute() uint64 }); ok {
		if n := se.sourceErrorsLastMinute(); n > 0 {
			r.SourceErrors = n
			if r.ErrLevel == "ok" {
				r.ErrLevel = "src"
			}
		}
	}
	if cfg.Offline {
		s.offlineRow(&r)
	}
	if s.status == Lost {
		r.Errors = fmt.Sprintf("silent %s", s.m.now.Sub(s.last).Round(time.Second))
		r.ErrLevel = "err"
	}
	r.Spark = make([]float64, 60)
	for i, b := range s.bucketsBack(60) {
		r.Spark[59-i] = float64(b.bytes) * 8
	}
	return r
}

// offlineRow turns a row's figures into whole-capture ones: the average
// rate over the stream's time in the file, and its errors in all of it.
func (s *Stream) offlineRow(r *Row) {
	dur := max(1, s.last.Sub(s.first).Seconds())
	r.BPS = float64(s.bytes) * 8 / dur
	r.PPS = float64(s.pkts) / dur
	if t, ok := s.dec.(interface{ errorsTotal() uint64 }); ok && r.Errors != "-" {
		n := t.errorsTotal()
		r.ErrorsLastMinute = n
		r.Errors = "0"
		if r.ErrLevel == "err" { // judged on the last minute; the total rules here
			r.ErrLevel = "ok"
		}
		if n > 0 {
			r.Errors, r.ErrLevel = fmt.Sprintf("%d in capture", n), "err"
		}
	}
}

func (s *Stream) detail(r Row, window int) *StreamDetail {
	d := &StreamDetail{Row: r}
	d.Detail.KV = []KV{
		{"Protocol", r.Proto},
		{"First seen", ago(s.m.now, s.first)},
		{"Last packet", ago(s.m.now, s.last)},
		{"Received", fmt.Sprintf("%d packets · %s", s.pkts, formatBytes(s.bytes))},
	}
	if s.payload > 0 && s.pkts > 0 {
		d.add("Payload rate", FormatRate(s.rateOver(cfgAvg(s))*float64(s.payload)/float64(s.bytes)))
	}
	if s.baseSecs >= 10 && s.kind.media() {
		d.add("Usual rate", FormatRate(s.baseline))
	}
	if s.vlan != 0 {
		d.add("VLAN", fmt.Sprint(s.vlan))
	}
	if dev := s.deviceName(); dev != "" {
		d.add("Sender's name", dev+" (announced over mDNS)")
	}
	if s.reason != "" {
		d.add("Problem", s.reason)
		if n := s.m.localWin.minute(); n > 0 && s.kind.media() {
			d.add("Caution", fmt.Sprintf("this machine dropped %d packets in the last minute before reading them, so some of these errors may be local, not on the network", n))
		}
	}
	if s.dec != nil {
		s.dec.describe(s, &d.Detail)
	}

	// The graph: whole seconds, or averaged into at most 300 points.
	if window < 10 {
		window = 60
	}
	if window > history {
		window = history
	}
	step := 1
	if window > 300 {
		step = window / 300
	}
	back := s.bucketsBack(window)
	n := window / step
	d.Series = make([]float64, n)
	for i := 0; i < n; i++ {
		var sum float64
		for j := 0; j < step; j++ {
			sum += float64(back[i*step+j].bytes) * 8
		}
		d.Series[n-1-i] = sum / float64(step)
	}
	d.Step = step

	d.Senders = Table{Title: "Senders", Cols: []string{"Sender", "Name", "Packets/s", "Rate", "Packets", "First seen", "Last"}}
	list := make([]*sender, 0, len(s.senders))
	for _, x := range s.senders {
		list = append(list, x)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].bytes > list[j].bytes })
	if len(list) > 200 {
		list = list[:200]
	}
	for _, x := range list {
		var b, p uint32
		for _, w := range x.win {
			b += w.bytes
			p += w.pkts
		}
		k := float64(len(x.win))
		d.Senders.Rows = append(d.Senders.Rows, []string{
			x.addr.String(), s.m.hostName(x.addr), fmt.Sprintf("%.1f", float64(p)/k), FormatRate(float64(b) * 8 / k),
			fmt.Sprint(x.pkts), ago(s.m.now, x.first), ago(s.m.now, x.last),
		})
	}
	return d
}

func cfgAvg(s *Stream) int { return int(math.Max(1, float64(s.m.cfg.AvgSeconds))) }

func formatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f kB", float64(b)/(1<<10))
	}
	return fmt.Sprintf("%d B", b)
}

// playURL is how VLC (and most players) are told to join the stream:
// udp://@group:port for raw MPEG-TS, rtp://@group:port for MPEG-TS over RTP.
func (s *Stream) playURL() string {
	scheme := ""
	switch d := s.dec.(type) {
	case *tsDec:
		scheme = "udp"
	case *rtpDec:
		if d.ts != nil {
			scheme = "rtp"
		}
	}
	if scheme == "" || s.key.Port == 0 {
		return ""
	}
	return fmt.Sprintf("%s://@%s", scheme, netip.AddrPortFrom(s.key.Dst, s.key.Port))
}
