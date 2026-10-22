package monitor

import (
	"fmt"
	"strings"
	"time"

	"github.com/andreacoppini/packhound/internal/mpegts"
	"github.com/andreacoppini/packhound/internal/pkt"
)

// ---- MPEG-TS ----

// tsDec follows a transport stream, and works out the Media Delivery Index
// (RFC 4445): the delay factor says how much buffering a receiver needs to
// ride out the stream's burstiness, the loss rate how many packets go
// missing a second.
type tsDec struct {
	base
	a *mpegts.Analyzer

	perDatagram int // TS packets in the latest datagram

	// Delay factor: a virtual buffer filled by arrivals and drained at the
	// stream's own rate; its swing over a second, in time, is the DF.
	ivStart  time.Time
	ivBytes  float64
	vbMin    float64
	vbMax    float64
	drain    float64 // bytes per second, from the previous second
	secBytes float64
	df       float64 // milliseconds, latest whole second
	haveDF   bool

	// Duplicated datagrams: the same datagram arriving twice, from a loop
	// or two paths to the receiver. Fed to the analyser twice it would read
	// as continuity errors, so a repeat is counted and skipped.
	// Only the last three are kept: a real duplicate arrives straight after
	// its original, while three is too short for an innocent repeat. No
	// non-null PID's counters can come back round in under four datagrams,
	// so two distinct datagrams are never identical within the window.
	recent [3]uint64
	next   int
	dups   uint64
	dupWin window
}

func newTS() *tsDec { return &tsDec{a: mpegts.NewAnalyzer()} }

func (t *tsDec) feed(_ *Stream, p *pkt.Packet) { t.feedTS(p.Time, p.Payload) }

func (t *tsDec) feedTS(at time.Time, b []byte) {
	if h, ok := datagramHash(b); ok {
		for _, x := range t.recent {
			if x == h {
				t.dups++
				t.dupWin.add(1)
				return
			}
		}
		t.recent[t.next] = h
		t.next = (t.next + 1) % len(t.recent)
	}
	if t.ivStart.IsZero() {
		t.ivStart = at
	}
	if t.drain > 0 {
		vb := t.ivBytes - t.drain*at.Sub(t.ivStart).Seconds()
		t.vbMin = min(t.vbMin, vb)
		t.vbMax = max(t.vbMax, vb+float64(len(b)))
	}
	t.ivBytes += float64(len(b))
	t.secBytes += float64(len(b))
	t.perDatagram = len(b) / mpegts.PacketSize
	t.a.Feed(b)
}

// datagramHash identifies a datagram for duplicate detection. A datagram of
// nothing but null packets is legitimately repeated, so it is not hashed.
func datagramHash(b []byte) (uint64, bool) {
	real := false
	for i := 0; i+3 < len(b); i += mpegts.PacketSize {
		if (uint16(b[i+1]&0x1f)<<8 | uint16(b[i+2])) != mpegts.NullPID {
			real = true
			break
		}
	}
	if !real {
		return 0, false
	}
	h := uint64(14695981039346656037)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h, true
}

func (t *tsDec) tick(_ *Stream, now time.Time) {
	t.a.Tick()
	t.dupWin.roll()
	if t.drain > 0 && t.ivBytes > 0 {
		t.df = (t.vbMax - t.vbMin) / t.drain * 1000
		t.haveDF = true
	}
	t.drain = t.secBytes
	t.secBytes = 0
	t.ivStart, t.ivBytes, t.vbMin, t.vbMax = now, 0, 0, 0
}

func (t *tsDec) name(*Stream) string { return t.a.ServiceName() }

func (t *tsDec) errorsLastMinute() (uint64, string) {
	if d := t.dupWin.minute(); d > 0 {
		return t.a.CCLastMinute() + d, "CC errors / duplicated datagrams"
	}
	return t.a.CCLastMinute(), "CC errors"
}

func (t *tsDec) describe(s *Stream, d *Detail) {
	for _, sv := range t.a.Services() {
		v := fmt.Sprintf("program %d", sv.Program)
		if sv.Name != "" {
			v = sv.Name + " · " + v
		}
		if sv.Provider != "" {
			v += " · " + sv.Provider
		}
		if sv.Type != "" {
			v += " · " + sv.Type
		}
		d.add("Service", v)
	}
	d.add("Video", t.a.VideoSummary())
	if t.a.TSID >= 0 {
		d.add("Transport stream ID", fmt.Sprint(t.a.TSID))
	}
	if t.haveDF {
		d.add("MDI (DF : MLR)", fmt.Sprintf("%.1f ms : %d", t.df, t.a.CCLastSecond()))
	}
	loss := t.a.CCErrors - t.a.CCQuirks
	d.add("CC errors (loss)", fmt.Sprintf("%d in the last minute · %d total · at least %d TS packets missing", t.a.CCLastMinute(), loss, t.a.Missing))
	if t.a.CCQuirks > 0 {
		d.add("CC quirks (no loss)", fmt.Sprintf("%d in the last minute · %d total: the encoder advances the counter on PCR-only packets; decoders ignore it", t.a.QuirksLastMinute(), t.a.CCQuirks))
	}
	if t.dups > 0 {
		d.add("Duplicated datagrams", fmt.Sprintf("%d in the last minute · %d total: the same datagram arrives twice (a loop, or two paths)", t.dupWin.minute(), t.dups))
	}
	if t.a.SyncErrors > 0 {
		d.add("Sync errors", fmt.Sprint(t.a.SyncErrors))
	}
	if t.a.TEIErrors > 0 {
		d.add("Transport errors (TEI)", fmt.Sprint(t.a.TEIErrors))
	}

	tb := Table{Title: "PIDs in the transport stream", Cols: []string{"PID", "Content", "Program", "Rate", "CC errors (loss)", "CC quirks"}}
	var scrambled []string
	for _, p := range t.a.PIDs() {
		kind := p.Kind
		if kind == "" {
			kind = "(not in PMT)"
		}
		if p.Lang != "" {
			kind += " (" + p.Lang + ")"
		}
		if p.Detail != "" {
			kind += " " + p.Detail
		}
		if p.Scrambled {
			kind += " · scrambled"
			scrambled = append(scrambled, fmt.Sprintf("0x%04X", p.PID))
		}
		prog, cc, q := "", fmt.Sprint(p.CCErrors-p.CCQuirks), fmt.Sprint(p.CCQuirks)
		if p.Program != 0 {
			prog = fmt.Sprint(p.Program)
		}
		if p.PID == mpegts.NullPID {
			cc, q = "-", "-"
		}
		tb.Rows = append(tb.Rows, []string{fmt.Sprintf("0x%04X", p.PID), kind, prog, FormatRate(p.Rate()), cc, q})
	}
	if len(scrambled) > 0 {
		d.add("Scrambled PIDs", strings.Join(scrambled, ", "))
	}
	d.Tables = append(d.Tables, tb)
}

// ---- RTP ----

type rtpHdr struct {
	pt      uint8
	seq     uint16
	ts      uint32
	ssrc    uint32
	payload []byte
}

// rtpHeader parses an RTP header, accepting only what is plausibly RTP: version
// 2, not an RTCP packet type, and a payload left over.
func rtpHeader(b []byte) (rtpHdr, bool) {
	if len(b) < 12 || b[0]>>6 != 2 {
		return rtpHdr{}, false
	}
	pt := b[1] & 0x7f
	if pt >= 72 && pt <= 76 { // RTCP sender/receiver reports land here
		return rtpHdr{}, false
	}
	n := 12 + 4*int(b[0]&0x0f)
	if b[0]&0x10 != 0 { // header extension
		if len(b) < n+4 {
			return rtpHdr{}, false
		}
		n += 4 + 4*int(u16(b[n+2:]))
	}
	end := len(b)
	if b[0]&0x20 != 0 { // padding
		if end == 0 || int(b[end-1]) > end-n {
			return rtpHdr{}, false
		}
		end -= int(b[end-1])
	}
	if n >= end {
		return rtpHdr{}, false
	}
	return rtpHdr{pt: pt, seq: u16(b[2:]), ts: u32(b[4:]), ssrc: u32(b[8:]), payload: b[n:end]}, true
}

// Static payload types (RFC 3551) worth naming.
var rtpPT = map[uint8]struct {
	name  string
	audio bool
}{
	0: {"PCMU", true}, 3: {"GSM", true}, 4: {"G723", true}, 8: {"PCMA", true}, 9: {"G722", true},
	10: {"L16 stereo", true}, 11: {"L16 mono", true}, 14: {"MPEG audio", true}, 18: {"G729", true},
	26: {"JPEG", false}, 31: {"H.261", false}, 32: {"MPEG video", false}, 33: {"MP2T", false}, 34: {"H.263", false},
}

type rtpDec struct {
	ts       *tsDec // when the payload is a transport stream
	pt       uint8
	ssrc     uint32
	lastSeq  int32 // -1 until seen
	lost     uint64
	dup      uint64
	reorder  uint64
	ssrcs    int
	lostWin  window
	guessed  bool // kind was guessed from packet size and rate
	sdpName  string
	sdpFmt   string
	payloadN int
}

func newRTP(pt uint8, payload []byte) *rtpDec {
	d := &rtpDec{pt: pt, lastSeq: -1}
	if pt == 33 || mpegts.LooksLikeTS(payload) {
		d.ts = newTS()
	}
	return d
}

func (r *rtpDec) classify(m *Monitor, k Key) (Kind, string) {
	if r.ts != nil {
		return KindVideo, "MPEG-TS / RTP"
	}
	if info, ok := m.sdpFor(k); ok {
		return r.fromSDP(info)
	}
	if p, ok := rtpPT[r.pt]; ok {
		if p.audio {
			return KindAudio, "RTP " + p.name
		}
		return KindVideo, "RTP " + p.name
	}
	return KindUnknown, fmt.Sprintf("RTP (PT %d)", r.pt)
}

func (r *rtpDec) fromSDP(info sdpInfo) (Kind, string) {
	r.sdpName, r.sdpFmt = info.Session, info.Format
	typ := "RTP"
	if strings.HasPrefix(info.Format, "L16") || strings.HasPrefix(info.Format, "L24") {
		typ = "AES67 / RTP"
	}
	switch info.Media {
	case "audio":
		return KindAudio, typ
	case "video":
		return KindVideo, typ
	}
	return KindUnknown, typ
}

func (r *rtpDec) feed(s *Stream, p *pkt.Packet) {
	h, ok := rtpHeader(p.Payload)
	if !ok {
		return
	}
	if h.ssrc != r.ssrc {
		r.ssrc, r.lastSeq = h.ssrc, -1
		r.ssrcs++
	}
	if r.lastSeq >= 0 {
		gap := h.seq - uint16(r.lastSeq) - 1
		switch {
		case gap == 0:
		case gap < 0x8000 && gap < 3000:
			r.lost += uint64(gap)
			r.lostWin.add(uint32(gap))
		case h.seq == uint16(r.lastSeq):
			r.dup++
			return
		default:
			r.reorder++
			return // late: do not move the sequence back
		}
	}
	r.lastSeq = int32(h.seq)
	r.payloadN = len(h.payload)
	if r.ts != nil {
		r.ts.feedTS(p.Time, h.payload)
	}
}

func (r *rtpDec) tick(s *Stream, now time.Time) {
	r.lostWin.roll()
	if r.ts != nil {
		r.ts.tick(s, now)
		return
	}
	// A stream that started before its SAP announcement was heard gets
	// relabelled once the announcement arrives.
	if r.sdpName == "" {
		if info, ok := s.m.sdpFor(s.key); ok {
			s.setKind(r.fromSDP(info))
			r.guessed = false
		}
	}
	// With nothing to go on, guess from the shape of the traffic after a few
	// seconds: audio is small packets at a fixed fast rate, video big ones.
	if s.kind == KindUnknown && now.Sub(s.first) > 3*time.Second {
		pps := s.ppsOver(3)
		switch {
		case pps >= 100 && r.payloadN <= 600:
			s.setKind(KindAudio, s.typ)
			r.guessed = true
		case pps >= 100:
			s.setKind(KindVideo, s.typ)
			r.guessed = true
		}
	}
}

func (r *rtpDec) name(s *Stream) string {
	if r.ts != nil {
		return r.ts.name(s)
	}
	return r.sdpName
}

func (r *rtpDec) errorsLastMinute() (uint64, string) {
	if r.ts != nil {
		cc, _ := r.ts.errorsLastMinute()
		return cc + r.lostWin.minute(), "lost packets / CC errors"
	}
	return r.lostWin.minute(), "lost RTP packets"
}

func (r *rtpDec) describe(s *Stream, d *Detail) {
	enc := fmt.Sprintf("RTP, payload type %d", r.pt)
	if p, ok := rtpPT[r.pt]; ok {
		enc += " (" + p.name + ")"
	}
	if r.sdpFmt != "" {
		enc += " · " + r.sdpFmt + " (from SAP)"
	}
	d.add("Encapsulation", enc)
	if r.ts == nil {
		if pps := s.ppsOver(3); pps >= 50 {
			d.add("Packet time", fmt.Sprintf("%.3g ms", 1000/pps))
		}
		if r.payloadN > 0 {
			d.add("Payload per packet", fmt.Sprintf("%d bytes", r.payloadN))
		}
		if r.guessed {
			d.add("Kind", fmt.Sprintf("guessed as %s from packet size and rate", s.kind))
		}
	}
	d.add("SSRC", fmt.Sprintf("0x%08X", r.ssrc))
	if r.ssrcs > 1 {
		d.add("SSRC changes", fmt.Sprint(r.ssrcs-1))
	}
	d.add("RTP packets lost", fmt.Sprintf("%d in the last minute · %d total", r.lostWin.minute(), r.lost))
	if r.reorder > 0 || r.dup > 0 {
		d.add("Out of order / duplicated", fmt.Sprintf("%d / %d", r.reorder, r.dup))
	}
	if r.ts != nil {
		r.ts.describe(s, d)
	}
}

// setKind changes what a stream is judged as, once more is known.
func (s *Stream) setKind(k Kind, typ string) {
	if s.kind == k && s.typ == typ {
		return
	}
	s.kind, s.typ = k, typ
	if k.media() && !(s.status == Receiving || s.status == Degraded || s.status == Lost) {
		s.status = Receiving
	}
}
