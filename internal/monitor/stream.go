package monitor

import (
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/andreacoppini/packhound/internal/pkt"
)

// history is how many one-second buckets each stream keeps: an hour, which
// is the longest window the console graphs.
const history = 3600

const maxSenders = 1024

type bucket struct {
	bytes uint32 // IP bytes
	pkts  uint32
}

// Status of a stream, from its traffic and the thresholds.
type Status string

const (
	Receiving Status = "Receiving"
	Degraded  Status = "Degraded"
	Lost      Status = "Lost"
	Periodic  Status = "Periodic"
	Quiet     Status = "Quiet"
)

func (s Status) level() string {
	switch s {
	case Receiving:
		return "ok"
	case Degraded:
		return "warn"
	case Lost:
		return "err"
	}
	return "idle"
}

// quietAfter is how long a periodic stream (discovery, routing) may say nothing
// before it is shown as Quiet. It is never an alert: these protocols are
// allowed to stop.
const quietAfter = 5 * time.Minute

// Stream is one group:port (or group and protocol, for non-UDP traffic).
type Stream struct {
	m    *Monitor
	key  Key
	kind Kind
	typ  string // "MPEG-TS / UDP", "mDNS" ...
	dec  decoder

	first, last time.Time
	pkts, bytes uint64
	payload     uint64 // UDP payload bytes, or IP payload for others

	ring    [history]bucket
	lastSec int64 // the second the ring is filling
	tickSec int64 // the second the last tick ran in

	senders map[netip.Addr]*sender
	vlan    uint16

	// Arrival-time jitter: the mean deviation of the gap between packets
	// from its own running average, smoothed as RFC 3550 smooths jitter.
	lastArrival time.Time
	meanIAT     float64 // seconds
	devIAT      float64

	baseline   float64 // bits per second, slow average while flowing
	baseSecs   int
	status     Status
	reason     string
	statusFrom time.Time
	resumed    time.Time // when the stream last came back from Lost
}

type sender struct {
	addr        netip.Addr
	pkts, bytes uint64
	first, last time.Time
	win         [5]bucket
	cur         bucket
}

func newStream(m *Monitor, k Key, p *pkt.Packet) *Stream {
	s := &Stream{m: m, key: k, first: p.Time, lastSec: p.Time.Unix(), tickSec: p.Time.Unix(), senders: map[netip.Addr]*sender{}, vlan: p.VLAN}
	s.kind, s.typ, s.dec = classify(m, k, p)
	if s.kind.media() {
		s.status = Receiving
	} else {
		s.status = Periodic
	}
	s.statusFrom = p.Time
	return s
}

func (s *Stream) ingest(p *pkt.Packet) {
	s.advance(p.Time.Unix())
	b := &s.ring[s.lastSec%history]
	b.bytes += uint32(p.IPLen)
	b.pkts++
	s.pkts++
	s.bytes += uint64(p.IPLen)
	s.payload += uint64(len(p.Payload))
	if p.Time.After(s.last) {
		s.last = p.Time
	}

	snd := s.senders[p.Src]
	if snd == nil {
		if len(s.senders) >= maxSenders {
			goto counted
		}
		snd = &sender{addr: p.Src, first: p.Time}
		s.senders[p.Src] = snd
		// A second source on a video or audio group is usually a
		// misconfigured encoder or a loop, and receivers will show garbage.
		if s.kind.media() && s.m.cfg.NewSenders && len(s.senders) > 1 && p.Time.Sub(s.first) > 10*time.Second {
			s.m.alert(p.Time, s, "warn", "New sender %s (now %d senders)", p.Src, len(s.senders))
		}
	}
	snd.pkts++
	snd.bytes += uint64(p.IPLen)
	snd.last = p.Time
	snd.cur.pkts++
	snd.cur.bytes += uint32(p.IPLen)
counted:

	if p.Frag == pkt.Later {
		return // no header to read, nothing for the decoder
	}
	if !s.lastArrival.IsZero() {
		d := p.Time.Sub(s.lastArrival).Seconds()
		if d >= 0 && d < 5 {
			if s.meanIAT == 0 {
				s.meanIAT = d
			}
			s.meanIAT += (d - s.meanIAT) / 16
			s.devIAT += (math.Abs(d-s.meanIAT) - s.devIAT) / 16
		}
	}
	s.lastArrival = p.Time
	if s.dec != nil {
		s.dec.feed(s, p)
	}
}

// advance moves the ring on to second sec, zeroing the seconds skipped.
// A packet stamped slightly in the past (timestamps from different CPUs) is
// counted in the current second rather than rewriting history.
func (s *Stream) advance(sec int64) {
	if sec <= s.lastSec {
		return
	}
	n := sec - s.lastSec
	if n > history {
		n = history
	}
	for i := int64(1); i <= n; i++ {
		s.ring[(s.lastSec+i)%history] = bucket{}
	}
	s.lastSec = sec
}

func (s *Stream) tick(now time.Time) {
	sec := now.Unix()
	s.advance(sec)
	if sec > s.tickSec {
		s.tickSec = sec
		for _, snd := range s.senders {
			copy(snd.win[1:], snd.win[:len(snd.win)-1])
			snd.win[0] = snd.cur
			snd.cur = bucket{}
		}
		if s.dec != nil {
			s.dec.tick(s, now)
		}
		// The baseline follows the rate slowly while the stream flows, so a
		// gradual change is accepted and a sudden drop stands out.
		// The first second is skipped: the stream started part way into it.
		// Until a minute has passed the baseline is a plain average.
		if r := s.rateOver(1); r > 0 && sec-1 > s.first.Unix() {
			s.baseSecs++
			s.baseline += (r - s.baseline) / float64(min(s.baseSecs, 60))
		}
	}
	s.judge(now)
}

// bucketsBack returns the n whole seconds before the current one, newest first.
func (s *Stream) bucketsBack(n int) []bucket {
	out := make([]bucket, n)
	for i := 0; i < n; i++ {
		out[i] = s.ring[((s.lastSec-1-int64(i))%history+history)%history]
	}
	return out
}

// rateOver is the IP bit rate averaged over the last n whole seconds.
func (s *Stream) rateOver(n int) float64 {
	var b uint64
	for _, x := range s.bucketsBack(n) {
		b += uint64(x.bytes)
	}
	return float64(b) * 8 / float64(n)
}

func (s *Stream) ppsOver(n int) float64 {
	var p uint64
	for _, x := range s.bucketsBack(n) {
		p += uint64(x.pkts)
	}
	return float64(p) / float64(n)
}

// judge works out the stream's status and raises alerts on changes.
func (s *Stream) judge(now time.Time) {
	cfg := s.m.cfg
	prev := s.status
	var next Status
	reason := ""
	silent := now.Sub(s.last)

	if !s.kind.media() {
		next = Periodic
		if silent > quietAfter {
			next = Quiet
		}
		s.setStatus(now, next, "", prev)
		return
	}

	switch {
	case silent > cfg.SilentAfter:
		next = Lost
		reason = fmt.Sprintf("no packets for %s", silent.Round(time.Second))
	default:
		if prev == Lost {
			s.resumed = now
		}
		next = Receiving
		errs := uint64(0)
		label := ""
		if s.dec != nil {
			errs, label = s.dec.errorsLastMinute()
		}
		if label != "" && errs > uint64(cfg.ErrPerMin) {
			next = Degraded
			reason = fmt.Sprintf("%d %s in the last minute", errs, label)
		}
		// The rate check needs three whole seconds of flow to average: not
		// while the stream may be stopping (Lost will say so), nor in the
		// first seconds after it comes back.
		flowing := silent < time.Second && now.Sub(s.resumed) > 4*time.Second
		if s.baseSecs >= 10 && cfg.DropPct > 0 && flowing {
			r := s.rateOver(3)
			if r < s.baseline*(1-cfg.DropPct/100) {
				next = Degraded
				drop := 100 * (1 - r/s.baseline)
				if reason != "" {
					reason += "; "
				}
				reason += fmt.Sprintf("rate %s, %.0f%% below its usual %s", FormatRate(r), drop, FormatRate(s.baseline))
			}
		}
	}
	s.reason = reason
	s.setStatus(now, next, reason, prev)
}

func (s *Stream) setStatus(now time.Time, next Status, reason string, prev Status) {
	if next == prev {
		return
	}
	s.status = next
	was := now.Sub(s.statusFrom).Round(time.Second)
	s.statusFrom = now
	if !s.kind.media() {
		return
	}
	switch {
	case next == Lost:
		s.m.alert(now, s, "err", "Stopped: %s", reason)
	case next == Degraded:
		s.m.alert(now, s, "warn", "Degraded: %s", reason)
	case prev == Lost:
		s.m.alert(now, s, "ok", "Back after %s", was)
	case prev == Degraded:
		s.m.alert(now, s, "ok", "Recovered after %s", was)
	}
}

func (s *Stream) name() string {
	if s.dec != nil {
		if n := s.dec.name(s); n != "" {
			return n
		}
	}
	return ""
}

func (s *Stream) groupLabel() string {
	g := s.key.Dst.String()
	if s.key.Dst == solicitedNode.Addr() {
		g = solicitedNode.String()
	}
	if s.key.Proto != pkt.ProtoUDP {
		return g
	}
	if s.key.Dst.Is6() {
		return fmt.Sprintf("[%s]:%d", g, s.key.Port)
	}
	return fmt.Sprintf("%s:%d", g, s.key.Port)
}

// FormatRate writes a bit rate the way network people read one.
func FormatRate(bps float64) string {
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.2f Gb/s", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.2f Mb/s", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.1f kb/s", bps/1e3)
	}
	return fmt.Sprintf("%.0f b/s", bps)
}
