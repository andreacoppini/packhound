package monitor

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/andreacoppini/packhound/internal/pkt"
)

// Row is one stream as the table shows it.
type Row struct {
	Key         string    `json:"key"`
	Family      int       `json:"family"` // 4 or 6
	Group       string    `json:"group"`
	Addr        string    `json:"addr"`
	Port        int       `json:"port"`
	Proto       string    `json:"proto"`
	Kind        Kind      `json:"kind"`
	Type        string    `json:"type"`
	Name        string    `json:"name"`
	Sender      string    `json:"sender"`
	Senders     int       `json:"senders"`
	BPS         float64   `json:"bps"`
	PPS         float64   `json:"pps"`
	AvgSize     int       `json:"avgSize"`
	JitterMs    float64   `json:"jitterMs"` // -1 when not meaningful
	Errors      string    `json:"errors"`
	ErrLevel    string    `json:"errLevel"`
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
	sort.Slice(snap.Rows, func(i, j int) bool {
		if snap.Rows[i].BPS != snap.Rows[j].BPS {
			return snap.Rows[i].BPS > snap.Rows[j].BPS
		}
		return snap.Rows[i].Key < snap.Rows[j].Key
	})
	snap.Alerts = append([]Alert(nil), m.alerts...)
	snap.Log = append([]LogLine(nil), m.log...)
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
			if errs > 0 {
				r.Errors = fmt.Sprintf("%d /min", errs)
				r.ErrLevel = "err"
			}
		}
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
	if s.reason != "" {
		d.add("Problem", s.reason)
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

	d.Senders = Table{Title: "Senders", Cols: []string{"Sender", "Packets/s", "Rate", "Packets", "First seen", "Last"}}
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
			x.addr.String(), fmt.Sprintf("%.1f", float64(p)/k), FormatRate(float64(b) * 8 / k),
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
