// Package monitor turns a flow of multicast packets into streams: what each
// group carries, how fast, from whom, and whether it is healthy.
//
// Everything here runs on packets already decoded by package pkt, from a live
// capture, sockets that joined groups, or the demo source. It does not care
// which.
package monitor

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/andreacoppini/packhound/internal/pkt"
)

// Kind is the broad family a stream belongs to. It decides how a stream is
// judged: media is expected to flow continuously and is alarmed when it stops,
// everything else speaks when it has something to say.
type Kind string

const (
	KindVideo     Kind = "video"
	KindAudio     Kind = "audio"
	KindDiscovery Kind = "disc"
	KindTiming    Kind = "time"
	KindNetwork   Kind = "net"
	KindUnknown   Kind = "unk"
)

func (k Kind) media() bool { return k == KindVideo || k == KindAudio }

// Config holds the alert thresholds, which the operator can change while
// running.
type Config struct {
	SilentAfter time.Duration // a media stream with no packets this long is Lost
	DropPct     float64       // rate this far below its baseline is Degraded
	ErrPerMin   int           // more errors than this in a minute is Degraded
	NewSenders  bool          // alert when a media stream gains a sender
	AvgSeconds  int           // rates shown are averaged over this many seconds
	// Offline is for a capture file read after the fact: rates are averaged
	// over each stream's time in the file, and errors are totals.
	Offline bool
}

// DefaultConfig is what the console starts with.
func DefaultConfig() Config {
	return Config{SilentAfter: 5 * time.Second, DropPct: 30, ErrPerMin: 0, NewSenders: true, AvgSeconds: 1}
}

// Key identifies a stream: a group, an IP protocol and, for UDP, a port.
type Key struct {
	Dst   netip.Addr
	Proto uint8
	Port  uint16
}

func (k Key) String() string {
	return fmt.Sprintf("%s|%d|%d", k.Dst, k.Proto, k.Port)
}

// solicitedNode is where IPv6 neighbour solicitations go: one group per
// address, so a busy segment has hundreds of them. They are folded into one
// stream or they would bury everything else.
var solicitedNode = netip.MustParsePrefix("ff02::1:ff00:0/104")

const (
	maxStreams = 4096
	maxAlerts  = 500
	maxLog     = 500
)

// Monitor holds every stream seen since Start.
type Monitor struct {
	mu      sync.Mutex
	cfg     Config
	streams map[Key]*Stream
	frags   map[fragKey]uint16
	sdp     map[string]sdpInfo    // "group:port" -> what SAP said about it
	hosts   map[netip.Addr]string // device names announced over mDNS
	alerts  []Alert
	log     []LogLine
	started time.Time
	now     time.Time // latest tick
	dropped uint64    // packets for streams beyond maxStreams

	// Packets lost on this machine before they could be read: the capture
	// buffer overflowed. Errors seen while this happens may not be real.
	localDrops    uint64
	localWin      window
	localUnlogged uint64
	localLogged   time.Time
}

// NoteLocalDrops records n packets lost on this machine in the second ending
// at now. Call it once a second, before Tick, with zero when nothing was lost.
func (m *Monitor) NoteLocalDrops(now time.Time, n uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.localWin.roll()
	if n == 0 {
		if m.localUnlogged > 0 && now.Sub(m.localLogged) >= 10*time.Second {
			m.logLocal(now)
		}
		return
	}
	m.localDrops += n
	m.localWin.add(uint32(n))
	m.localUnlogged += n
	// One line at most every ten seconds, however long the overload lasts.
	if now.Sub(m.localLogged) >= 10*time.Second {
		m.logLocal(now)
	}
}

func (m *Monitor) logLocal(now time.Time) {
	m.logf(now, "This machine dropped %d packets before Packhound could read them (capture buffer full). Errors on streams at the same time may not be on the network.", m.localUnlogged)
	m.localUnlogged = 0
	m.localLogged = now
}

// noteHost records the name a device announced for its address (mDNS), so
// other streams can say which device sends them. Called under m.mu.
func (m *Monitor) noteHost(a netip.Addr, name string) {
	if !a.IsValid() || name == "" {
		return
	}
	if m.hosts == nil || len(m.hosts) >= 4096 {
		m.hosts = map[netip.Addr]string{}
	}
	m.hosts[a.Unmap()] = name
}

// hostName is the announced name for an address, or "". Called under m.mu.
func (m *Monitor) hostName(a netip.Addr) string { return m.hosts[a.Unmap()] }

type fragKey struct {
	src netip.Addr
	id  uint32
}

// Alert is a change in a stream's health worth telling someone about.
type Alert struct {
	Time    time.Time `json:"time"`
	Key     string    `json:"key"`
	Group   string    `json:"group"`
	Name    string    `json:"name"`
	Level   string    `json:"level"` // ok, warn, err
	Message string    `json:"message"`
}

// LogLine is an event in the monitor's own log.
type LogLine struct {
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
}

func New(cfg Config) *Monitor {
	return &Monitor{
		cfg:     cfg,
		streams: map[Key]*Stream{},
		frags:   map[fragKey]uint16{},
		sdp:     map[string]sdpInfo{},
	}
}

// SetConfig changes the thresholds; they apply from the next tick.
func (m *Monitor) SetConfig(c Config) {
	if c.AvgSeconds < 1 {
		c.AvgSeconds = 1
	}
	if c.AvgSeconds > 60 {
		c.AvgSeconds = 60
	}
	m.mu.Lock()
	m.cfg = c
	m.mu.Unlock()
}

func (m *Monitor) Config() Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

// Logf adds a line to the log the console shows.
func (m *Monitor) Logf(format string, a ...any) {
	m.LogAt(time.Now(), format, a...)
}

// LogAt adds a line to the log, stamped t: for a capture file, the time in
// the capture it is about.
func (m *Monitor) LogAt(t time.Time, format string, a ...any) {
	m.mu.Lock()
	m.logf(t, format, a...)
	m.mu.Unlock()
}

func (m *Monitor) logf(t time.Time, format string, a ...any) {
	m.log = append(m.log, LogLine{Time: t, Message: fmt.Sprintf(format, a...)})
	if len(m.log) > maxLog {
		m.log = append([]LogLine(nil), m.log[len(m.log)-maxLog:]...)
	}
}

// Reset forgets every stream, alert and log line.
func (m *Monitor) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streams = map[Key]*Stream{}
	m.frags = map[fragKey]uint16{}
	m.sdp = map[string]sdpInfo{}
	m.hosts = nil
	m.alerts = nil
	m.log = nil
	m.started = time.Time{}
	m.dropped = 0
	m.localDrops, m.localWin, m.localUnlogged, m.localLogged = 0, window{}, 0, time.Time{}
}

// Ingest takes one packet. The packet's payload is not kept.
func (m *Monitor) Ingest(p *pkt.Packet) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ingest(p)
}

// IngestBatch takes a run of packets under one lock.
func (m *Monitor) IngestBatch(ps []pkt.Packet) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range ps {
		m.ingest(&ps[i])
	}
}

func (m *Monitor) ingest(p *pkt.Packet) {
	if m.started.IsZero() {
		m.started = p.Time
	}

	port := p.DstPort
	switch p.Frag {
	case pkt.First:
		if len(m.frags) > 8192 {
			m.frags = map[fragKey]uint16{}
		}
		m.frags[fragKey{p.Src, p.FragID}] = port
	case pkt.Later:
		port = m.frags[fragKey{p.Src, p.FragID}]
	}

	dst := p.Dst
	if dst.Is6() && solicitedNode.Contains(dst) {
		dst = solicitedNode.Addr()
	}
	k := Key{Dst: dst, Proto: p.Proto, Port: port}
	s := m.streams[k]
	if s == nil {
		if len(m.streams) >= maxStreams {
			m.dropped++
			return
		}
		s = newStream(m, k, p)
		m.streams[k] = s
		m.logf(p.Time, "New stream %s: %s from %s", s.groupLabel(), s.typ, p.Src)
	}
	s.ingest(p)
}

// Tick moves every stream on to the second containing now and works out
// health. Call it once a second.
func (m *Monitor) Tick(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = now
	for _, s := range m.streams {
		s.tick(now)
	}
}

func (m *Monitor) alert(t time.Time, s *Stream, level, format string, a ...any) {
	al := Alert{Time: t, Key: s.key.String(), Group: s.groupLabel(), Name: s.name(), Level: level, Message: fmt.Sprintf(format, a...)}
	m.alerts = append(m.alerts, al)
	if len(m.alerts) > maxAlerts {
		m.alerts = append([]Alert(nil), m.alerts[len(m.alerts)-maxAlerts:]...)
	}
	m.logf(t, "%s %s: %s", al.Group, al.Name, al.Message)
}

// registerSDP records what a SAP announcement says a group carries, and
// relabels the stream if it is already being received.
func (m *Monitor) registerSDP(info sdpInfo) {
	id := fmt.Sprintf("%s:%d", info.Group, info.Port)
	m.sdp[id] = info
	if len(m.sdp) > 1024 {
		m.sdp = map[string]sdpInfo{id: info}
	}
}

func (m *Monitor) sdpFor(k Key) (sdpInfo, bool) {
	i, ok := m.sdp[fmt.Sprintf("%s:%d", k.Dst, k.Port)]
	return i, ok
}
