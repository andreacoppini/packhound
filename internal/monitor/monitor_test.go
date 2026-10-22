package monitor

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/andreacoppini/packhound/internal/mpegts"
	"github.com/andreacoppini/packhound/internal/pkt"
)

var t0 = time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)

// feeder sends a TS channel at a steady packet rate on a simulated clock,
// ticking the monitor every whole second the way the engine does.
type feeder struct {
	m    *Monitor
	mux  *mpegts.Muxer
	now  time.Time
	src  netip.Addr
	dst  netip.Addr
	sent bool
}

func newFeeder(m *Monitor) *feeder {
	return &feeder{m: m, mux: mpegts.NewMuxer(), now: t0, src: netip.MustParseAddr("10.0.0.1"), dst: netip.MustParseAddr("239.1.1.1")}
}

// run advances the clock by d, sending pps datagrams a second (0 for none).
func (f *feeder) run(d time.Duration, pps int) {
	end := f.now.Add(d)
	step := 10 * time.Millisecond
	if pps > 0 {
		step = time.Second / time.Duration(pps)
	}
	for f.now.Before(end) {
		next := f.now.Add(step)
		if next.Unix() > f.now.Unix() {
			f.m.Tick(time.Unix(next.Unix(), 0))
		}
		f.now = next
		if pps == 0 {
			continue
		}
		var payload []byte
		if !f.sent {
			for _, p := range f.mux.Section(0, mpegts.PAT(1, 1, 0x100)) {
				payload = append(payload, p...)
			}
			f.sent = true
		}
		for len(payload) < 7*188 {
			payload = append(payload, f.mux.PES(0x101, 0xe0, make([]byte, 150))[0]...)
		}
		f.m.Ingest(&pkt.Packet{Time: f.now, Src: f.src, Dst: f.dst, Proto: pkt.ProtoUDP, DstPort: 5000, SrcPort: 1000, IPLen: 28 + 7*188, Payload: payload[:7*188]})
	}
}

func (f *feeder) row(t *testing.T) Row {
	t.Helper()
	snap := f.m.Snapshot("", 60)
	for _, r := range snap.Rows {
		if r.Addr == f.dst.String() {
			return r
		}
	}
	t.Fatal("stream not found")
	return Row{}
}

func alertsText(m *Monitor) string {
	var b strings.Builder
	for _, a := range m.Snapshot("", 60).Alerts {
		b.WriteString(a.Level + ": " + a.Message + "\n")
	}
	return b.String()
}

func TestSteadyStreamIsReceiving(t *testing.T) {
	m := New(DefaultConfig())
	f := newFeeder(m)
	f.run(20*time.Second, 100)
	r := f.row(t)
	if r.Status != Receiving || r.Kind != KindVideo || r.Type != "MPEG-TS / UDP" {
		t.Fatalf("row %+v", r)
	}
	if want := 100.0 * (28 + 7*188) * 8; r.BPS < want*0.98 || r.BPS > want*1.02 {
		t.Fatalf("rate %.0f, want about %.0f", r.BPS, want)
	}
	if r.PPS < 99 || r.PPS > 101 {
		t.Fatalf("pps %.1f", r.PPS)
	}
	if a := alertsText(m); a != "" {
		t.Fatalf("alerts on a steady stream:\n%s", a)
	}
}

func TestLostAndBack(t *testing.T) {
	m := New(DefaultConfig())
	f := newFeeder(m)
	f.run(20*time.Second, 100)
	f.run(8*time.Second, 0)
	if r := f.row(t); r.Status != Lost || !strings.HasPrefix(r.Errors, "silent") {
		t.Fatalf("after silence: %+v", r)
	}
	f.run(5*time.Second, 100)
	if r := f.row(t); r.Status != Receiving {
		t.Fatalf("after return: %s %s", r.Status, r.Reason)
	}
	a := alertsText(m)
	if !strings.Contains(a, "err: Stopped: no packets for 6s") || !strings.Contains(a, "ok: Back after") {
		t.Fatalf("alerts:\n%s", a)
	}
}

func TestRateDropDegrades(t *testing.T) {
	m := New(DefaultConfig())
	f := newFeeder(m)
	f.run(30*time.Second, 100)
	f.run(5*time.Second, 40)
	r := f.row(t)
	if r.Status != Degraded || !strings.Contains(r.Reason, "below its usual") {
		t.Fatalf("after a drop: %s %q", r.Status, r.Reason)
	}
	f.run(5*time.Second, 100)
	if r := f.row(t); r.Status != Receiving {
		t.Fatalf("after recovery: %s %q", r.Status, r.Reason)
	}
	if a := alertsText(m); !strings.Contains(a, "warn: Degraded: rate") || !strings.Contains(a, "ok: Recovered") {
		t.Fatalf("alerts:\n%s", a)
	}
}

func TestCCErrorsDegrade(t *testing.T) {
	m := New(DefaultConfig())
	f := newFeeder(m)
	f.run(5*time.Second, 100)
	// One datagram lost on the way: the muxer made it, nobody received it.
	f.mux.PES(0x101, 0xe0, make([]byte, 150))
	f.run(2*time.Second, 100)
	r := f.row(t)
	if r.Status != Degraded || r.Errors != "1 /min" || !strings.Contains(r.Reason, "1 CC errors") {
		t.Fatalf("row %s %q %q", r.Status, r.Errors, r.Reason)
	}
	// A minute later the error has aged out.
	f.run(62*time.Second, 100)
	if r := f.row(t); r.Status != Receiving {
		t.Fatalf("after a clean minute: %s %q", r.Status, r.Reason)
	}
}

func TestSenderMadeErrorsDoNotDegrade(t *testing.T) {
	m := New(DefaultConfig())
	f := newFeeder(m)
	f.run(5*time.Second, 100)
	// The 52nd packet is mid-datagram: the jump sits between two packets
	// that arrived together, so the sender made it.
	n := 0
	f.mux.SkipCC = func(uint16) bool { n++; return n == 52 }
	f.run(2*time.Second, 100)
	r := f.row(t)
	if r.Status != Receiving || r.Errors != "0" || r.SourceErrors != 1 || r.ErrLevel != "src" {
		t.Fatalf("row %s %q source %d level %s", r.Status, r.Errors, r.SourceErrors, r.ErrLevel)
	}
}

func TestSecondSenderAlerts(t *testing.T) {
	m := New(DefaultConfig())
	f := newFeeder(m)
	f.run(15*time.Second, 50)
	f.src = netip.MustParseAddr("10.0.0.99")
	f.run(time.Second, 50)
	if a := alertsText(m); !strings.Contains(a, "New sender 10.0.0.99 (now 2 senders)") {
		t.Fatalf("alerts:\n%s", a)
	}
	if r := f.row(t); r.Senders != 2 || r.Sender != "2 senders" {
		t.Fatalf("row senders %d %q", r.Senders, r.Sender)
	}
}

func TestSolicitedNodeGroupsFold(t *testing.T) {
	m := New(DefaultConfig())
	for _, g := range []string{"ff02::1:ff00:1", "ff02::1:ffab:cdef", "ff02::1:ff12:3456"} {
		m.Ingest(&pkt.Packet{Time: t0, Src: netip.MustParseAddr("fe80::1"), Dst: netip.MustParseAddr(g), Proto: pkt.ProtoICMPv6, IPLen: 72, Payload: make([]byte, 24)})
	}
	snap := m.Snapshot("", 60)
	if len(snap.Rows) != 1 || snap.Rows[0].Group != "ff02::1:ff00:0/104" || snap.Rows[0].Family != 6 {
		t.Fatalf("rows %+v", snap.Rows)
	}
}

func TestPeriodicStreamsNeverAlert(t *testing.T) {
	m := New(DefaultConfig())
	p := &pkt.Packet{Time: t0, Src: netip.MustParseAddr("10.0.0.5"), Dst: netip.MustParseAddr("224.0.0.251"), Proto: pkt.ProtoUDP, SrcPort: 5353, DstPort: 5353, IPLen: 40, Payload: make([]byte, 12)}
	m.Ingest(p)
	for i := 1; i < 400; i++ {
		m.Tick(t0.Add(time.Duration(i) * time.Second))
	}
	snap := m.Snapshot("", 60)
	if snap.Rows[0].Status != Quiet || len(snap.Alerts) != 0 {
		t.Fatalf("status %s, %d alerts", snap.Rows[0].Status, len(snap.Alerts))
	}
}

func TestSAPRelabelsRTP(t *testing.T) {
	m := New(DefaultConfig())
	rtp := make([]byte, 12+288)
	rtp[0], rtp[1] = 0x80, 97
	dst := netip.MustParseAddr("239.69.83.67")
	m.Ingest(&pkt.Packet{Time: t0, Src: netip.MustParseAddr("10.0.0.7"), Dst: dst, Proto: pkt.ProtoUDP, DstPort: 5004, IPLen: 328, Payload: rtp})
	if r := m.Snapshot("", 60).Rows[0]; r.Kind != KindUnknown || r.Type != "RTP (PT 97)" {
		t.Fatalf("before SAP: %s %s", r.Kind, r.Type)
	}
	sdp := "v=0\r\no=- 1 1 IN IP4 10.0.0.7\r\ns=Bar-Mix\r\nc=IN IP4 239.69.83.67/32\r\nt=0 0\r\nm=audio 5004 RTP/AVP 97\r\na=rtpmap:97 L24/48000/2\r\n"
	sap := append([]byte{0x20, 0, 0, 1, 10, 0, 0, 7}, "application/sdp\x00"+sdp...)
	m.Ingest(&pkt.Packet{Time: t0, Src: netip.MustParseAddr("10.0.0.7"), Dst: netip.MustParseAddr("239.255.255.255"), Proto: pkt.ProtoUDP, DstPort: 9875, IPLen: 28 + len(sap), Payload: sap})
	m.Tick(t0.Add(time.Second))
	snap := m.Snapshot("239.69.83.67|17|5004", 60)
	var r Row
	for _, x := range snap.Rows {
		if x.Addr == "239.69.83.67" {
			r = x
		}
	}
	if r.Kind != KindAudio || r.Type != "AES67 / RTP" || r.Name != "Bar-Mix" {
		t.Fatalf("after SAP: %s %s %q", r.Kind, r.Type, r.Name)
	}
}

func TestFragmentsFollowTheirFirst(t *testing.T) {
	m := New(DefaultConfig())
	src, dst := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("239.9.9.9")
	m.Ingest(&pkt.Packet{Time: t0, Src: src, Dst: dst, Proto: pkt.ProtoUDP, DstPort: 6000, IPLen: 1500, Payload: make([]byte, 1472), Frag: pkt.First, FragID: 9})
	m.Ingest(&pkt.Packet{Time: t0, Src: src, Dst: dst, Proto: pkt.ProtoUDP, IPLen: 600, Payload: make([]byte, 580), Frag: pkt.Later, FragID: 9})
	snap := m.Snapshot("", 60)
	if len(snap.Rows) != 1 || snap.Rows[0].Packets != 2 || snap.Rows[0].Bytes != 2100 {
		t.Fatalf("rows %+v", snap.Rows)
	}
}

func TestEmptySnapshotListsAreNotNil(t *testing.T) {
	snap := New(DefaultConfig()).Snapshot("", 60)
	if snap.Rows == nil || snap.Alerts == nil || snap.Log == nil {
		t.Fatal("an empty snapshot must have empty lists, not nil: the console reads them as JSON arrays")
	}
}

func TestDuplicatedDatagramsAreNotCCErrors(t *testing.T) {
	m := New(DefaultConfig())
	mux := mpegts.NewMuxer()
	src, dst := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("239.1.1.1")
	now := t0
	for i := 0; i < 200; i++ {
		var b []byte
		for j := 0; j < 7; j++ {
			b = append(b, mux.PES(0x100, 0xe0, []byte{byte(i), byte(j)})[0]...)
		}
		p := &pkt.Packet{Time: now, Src: src, Dst: dst, Proto: pkt.ProtoUDP, DstPort: 5000, IPLen: 28 + len(b), Payload: b}
		m.Ingest(p)
		if i%10 == 0 {
			m.Ingest(p) // the network delivers this one twice
		}
		now = now.Add(5 * time.Millisecond)
	}
	m.Tick(now.Add(time.Second))
	snap := m.Snapshot("239.1.1.1|17|5000", 60)
	r := snap.Rows[0]
	if r.Errors != "20 /min" || !strings.Contains(r.Reason, "duplicated datagrams") {
		t.Fatalf("errors %q reason %q", r.Errors, r.Reason)
	}
	for _, kv := range snap.Detail.KV {
		if kv.K == "CC errors (loss)" && !strings.HasPrefix(kv.V, "0 in the last minute") {
			t.Fatalf("duplicates counted as CC errors: %s", kv.V)
		}
	}
}
