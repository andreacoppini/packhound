// Package mpegts reads what an IPTV operator wants to know from a transport
// stream as it goes past: which programmes and elementary streams it carries,
// what the service is called, how fast each PID runs, and whether packets are
// going missing (continuity-counter errors, the first thing TR 101 290 checks).
//
// It analyses; it never demultiplexes or decodes media beyond the H.264
// sequence parameter set that gives the picture size.
package mpegts

import (
	"fmt"
	"sort"
	"strings"
)

const (
	PacketSize = 188
	SyncByte   = 0x47
	NullPID    = 0x1fff
	patPID     = 0x0000
	sdtPID     = 0x0011
)

// LooksLikeTS reports whether b is a whole number of TS packets, each starting
// with the sync byte. One datagram is enough to tell: raw IPTV carries seven
// packets per datagram, and nothing else lines up 0x47 every 188 bytes.
func LooksLikeTS(b []byte) bool {
	if len(b) < PacketSize || len(b)%PacketSize != 0 {
		return false
	}
	for i := 0; i < len(b); i += PacketSize {
		if b[i] != SyncByte {
			return false
		}
	}
	return true
}

// PID is what is known about one packet identifier.
type PID struct {
	PID      uint16
	Packets  uint64
	CCErrors uint64 // every continuity error, as TR 101 290 counts them
	CCQuirks uint64 // of which: the counter advanced on a packet with no payload
	CCSource uint64 // of which: jumps made by the sender, the stream being whole
	// Scrambled is true while the PID is scrambled: most of its packets
	// over the last five whole seconds were. A headend that loses its
	// source or its conditional access for a moment comes back clear, and
	// so does this.
	Scrambled        bool
	ScrambledPackets uint64 // since the start
	Kind             string // "PAT", "PMT", "H.264 video" ...
	Lang             string
	Program          uint16
	StreamType       uint8
	Detail           string // picture size for video, when known

	lastCC   int8 // -1 until seen
	dupSeen  bool
	lastDg   uint64    // datagram the PID was last seen in
	window   [5]uint32 // packets in each of the last five whole seconds
	thisSec  uint32
	scrWin   [5]uint32 // of which scrambled
	scrSec   uint32
	ticked   bool   // a whole second has passed: Scrambled reads the window
	section  []byte // PSI section being reassembled
	sectLeft int
	h264     h264Scan
}

// Rate is the PID's average bit rate over the last five whole seconds.
func (p *PID) Rate() float64 {
	var n uint32
	for _, c := range p.window {
		n += c
	}
	return float64(n) * PacketSize * 8 / float64(len(p.window))
}

// Service is a programme in the stream, named from the SDT where present.
type Service struct {
	Program  uint16
	PMTPID   uint16
	PCRPID   uint16
	Name     string
	Provider string
	Type     string
}

// Analyzer follows one transport stream.
type Analyzer struct {
	pids     map[uint16]*PID
	pmtPIDs  map[uint16]uint16 // PMT PID -> program number
	services map[uint16]*Service
	TSID     int // -1 until the PAT is seen

	Packets      uint64
	SyncErrors   uint64
	CCErrors     uint64 // every continuity error, as TR 101 290 counts them
	CCQuirks     uint64 // of which: encoder quirks, nothing missing
	CCSource     uint64 // of which: jumps the sender made, nothing lost on the way
	Missing      uint64 // TS packets the counter jumps say never arrived
	TEIErrors    uint64 // packets the modulator marked uncorrectable
	ccThisSecond uint64
	ccWindow     [60]uint32 // CC errors that mean loss, per second, last minute
	ccIdx        int
	qThisSecond  uint64
	qWindow      [60]uint32 // quirks per second, last minute
	sThisSecond  uint64
	sWindow      [60]uint32 // sender-made jumps per second, last minute

	// Telling loss on the way from jumps the sender made. A datagram is lost
	// or delivered whole, so every PID with packets in a lost datagram jumps
	// at the same point. When some other PID steps cleanly from the
	// previous datagram into this one, nothing went missing in between, and
	// a jump on any PID there was made by the sender.
	dg      uint64      // datagrams fed so far
	clean   bool        // the boundary into this datagram is proven whole
	unclean [1024]bool  // per recent datagram: boundary into it not proven
	pending []pendingCC // jumps in this datagram, classified at its end

	grab *grab // a key picture being collected for a thumbnail
}

type pendingCC struct {
	p       *PID
	missing int
	since   uint64 // the datagram the PID was last seen in before the jump
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		pids:     map[uint16]*PID{},
		pmtPIDs:  map[uint16]uint16{},
		services: map[uint16]*Service{},
		TSID:     -1,
	}
}

// Feed takes the payload of one datagram: a run of 188-byte packets. A tail
// that is not a whole packet is counted as a sync error and dropped.
func (a *Analyzer) Feed(b []byte) {
	a.dg++
	a.clean = false
	a.pending = a.pending[:0]
	for len(b) >= PacketSize {
		if b[0] != SyncByte {
			a.SyncErrors++
			// Resynchronise on the next sync byte rather than giving up on
			// the rest of the datagram.
			i := 1
			for i < len(b) && b[i] != SyncByte {
				i++
			}
			b = b[i:]
			continue
		}
		a.packet(b[:PacketSize])
		b = b[PacketSize:]
	}
	if len(b) > 0 {
		a.SyncErrors++
	}
	a.unclean[a.dg%uint64(len(a.unclean))] = !a.clean
	for _, e := range a.pending {
		if a.wholeSince(e.since) {
			a.sourceError(e.p)
		} else {
			a.ccError(e.p, e.missing)
		}
	}
}

// wholeSince reports whether every datagram boundary after datagram since,
// up to and including the current one, is proven whole.
func (a *Analyzer) wholeSince(since uint64) bool {
	if a.dg-since >= uint64(len(a.unclean)) {
		return false
	}
	for k := since + 1; k <= a.dg; k++ {
		if a.unclean[k%uint64(len(a.unclean))] {
			return false
		}
	}
	return true
}

// Tick closes a one-second interval: per-PID rates and the CC error history
// move on by one.
func (a *Analyzer) Tick() {
	for _, p := range a.pids {
		copy(p.window[1:], p.window[:len(p.window)-1])
		p.window[0] = p.thisSec
		p.thisSec = 0
		copy(p.scrWin[1:], p.scrWin[:len(p.scrWin)-1])
		p.scrWin[0] = p.scrSec
		p.scrSec = 0
		var n, s uint32
		for i := range p.window {
			n += p.window[i]
			s += p.scrWin[i]
		}
		p.Scrambled = 2*s > n
		p.ticked = true
	}
	a.ccIdx = (a.ccIdx + 1) % len(a.ccWindow)
	a.ccWindow[a.ccIdx] = uint32(a.ccThisSecond)
	a.ccThisSecond = 0
	a.qWindow[a.ccIdx] = uint32(a.qThisSecond)
	a.qThisSecond = 0
	a.sWindow[a.ccIdx] = uint32(a.sThisSecond)
	a.sThisSecond = 0
}

// SourceLastMinute counts, over the last 60 seconds, continuity jumps made by
// the sender: the stream around them arrived whole, so nothing was lost on
// the network, but the sender skipped or repeated packets.
func (a *Analyzer) SourceLastMinute() uint64 {
	n := a.sThisSecond
	for _, c := range a.sWindow {
		n += uint64(c)
	}
	return n
}

// QuirksLastMinute counts, over the last 60 seconds, continuity errors that
// lose nothing: the encoder advanced the counter on a packet carrying only an
// adaptation field (typically a PCR), which the standard says it must not.
// Decoders ignore it, so it is reported apart from loss.
func (a *Analyzer) QuirksLastMinute() uint64 {
	n := a.qThisSecond
	for _, c := range a.qWindow {
		n += uint64(c)
	}
	return n
}

// CCLastMinute is the number of continuity errors in the last 60 seconds
// that mean packets went missing (quirks are not counted).
func (a *Analyzer) CCLastMinute() uint64 {
	var n uint64
	for _, c := range a.ccWindow {
		n += uint64(c)
	}
	return n + a.ccThisSecond
}

// ScrambledNow reports whether the stream's video, and its audio, are
// scrambled now: some PID of that kind is.
func (a *Analyzer) ScrambledNow() (video, audio bool) {
	for _, p := range a.pids {
		if !p.Scrambled {
			continue
		}
		switch {
		case strings.Contains(p.Kind, "video"):
			video = true
		case strings.Contains(p.Kind, "audio"):
			audio = true
		}
	}
	return video, audio
}

// ScrambledPackets counts the scrambled packets seen on any PID.
func (a *Analyzer) ScrambledPackets() uint64 {
	var n uint64
	for _, p := range a.pids {
		n += p.ScrambledPackets
	}
	return n
}

// CCLastSecond is the number of continuity errors in the last whole second.
func (a *Analyzer) CCLastSecond() uint32 { return a.ccWindow[a.ccIdx] }

func (a *Analyzer) pid(n uint16) *PID {
	p := a.pids[n]
	if p == nil {
		p = &PID{PID: n, lastCC: -1}
		switch n {
		case patPID:
			p.Kind = "PAT"
		case 0x0001:
			p.Kind = "CAT"
		case sdtPID:
			p.Kind = "SDT / BAT"
		case 0x0012:
			p.Kind = "EIT"
		case 0x0014:
			p.Kind = "TDT / TOT"
		case NullPID:
			p.Kind = "Null padding"
		}
		if prog, ok := a.pmtPIDs[n]; ok {
			p.Kind, p.Program = "PMT", prog
		}
		a.pids[n] = p
	}
	return p
}

func (a *Analyzer) packet(b []byte) {
	a.Packets++
	tei := b[1]&0x80 != 0
	pusi := b[1]&0x40 != 0
	pidN := uint16(b[1]&0x1f)<<8 | uint16(b[2])
	scr := b[3] >> 6
	afc := (b[3] >> 4) & 3
	cc := int8(b[3] & 0x0f)

	p := a.pid(pidN)
	p.Packets++
	p.thisSec++
	if tei {
		a.TEIErrors++
	}
	if scr != 0 {
		p.ScrambledPackets++
		p.scrSec++
	}
	if !p.ticked { // until the first whole second, the latest packet says
		p.Scrambled = scr != 0
	}

	payload := b[4:]
	discontinuity := false
	if afc&2 != 0 { // adaptation field present
		if len(payload) < 1 {
			return
		}
		al := int(payload[0])
		if al > 0 && len(payload) > 1 {
			discontinuity = payload[1]&0x80 != 0
		}
		if 1+al > len(payload) {
			return
		}
		payload = payload[1+al:]
	}
	hasPayload := afc&1 != 0

	// Continuity: the counter advances only on packets with payload. One
	// repeat of the previous value is a legal duplicate; the null PID is
	// not counted at all.
	if pidN != NullPID {
		first := p.lastDg != a.dg // first packet of this PID in the datagram
		jump := -1                // packets skipped, when the counter jumps
		switch {
		case p.lastCC < 0 || discontinuity:
		case !hasPayload:
			switch cc {
			case p.lastCC:
			case (p.lastCC + 1) & 0x0f:
				a.ccQuirk(p)
			default:
				jump = int((cc - p.lastCC - 1) & 0x0f)
			}
		case cc == p.lastCC:
			if p.dupSeen {
				jump = 0
			}
			p.dupSeen = true
		case cc != (p.lastCC+1)&0x0f:
			jump = int((cc - p.lastCC - 1) & 0x0f)
			p.dupSeen = false
		default:
			p.dupSeen = false
		}
		// A PID stepping cleanly out of the previous datagram proves the
		// boundary between them whole.
		if first && jump < 0 && p.lastCC >= 0 && p.lastDg == a.dg-1 {
			a.clean = true
		}
		if jump >= 0 {
			a.pending = append(a.pending, pendingCC{p: p, missing: jump, since: p.lastDg})
		}
		p.lastCC = cc
		p.lastDg = a.dg
	}

	if !hasPayload || scr != 0 {
		return
	}
	if a.grab != nil && pidN == a.grab.pid {
		a.grab.packet(payload, pusi)
	}
	switch {
	case pidN == patPID, pidN == sdtPID, p.Kind == "PMT":
		a.psi(p, payload, pusi)
	case p.StreamType == 0x1b:
		if p.Detail == "" {
			p.h264.feed(payload, pusi)
			if s := p.h264.result; s != "" {
				p.Detail = s
			}
		}
	}
}

// ccError counts a continuity error that means loss; missing is how many
// packets the jump skips (modulo 16, so a lower bound).
func (a *Analyzer) ccError(p *PID, missing int) {
	p.CCErrors++
	a.CCErrors++
	a.Missing += uint64(missing)
	a.ccThisSecond++
}

func (a *Analyzer) sourceError(p *PID) {
	p.CCErrors++
	p.CCSource++
	a.CCErrors++
	a.CCSource++
	a.sThisSecond++
}

func (a *Analyzer) ccQuirk(p *PID) {
	p.CCErrors++
	p.CCQuirks++
	a.CCErrors++
	a.CCQuirks++
	a.qThisSecond++
}

// psi reassembles sections on a PSI PID and hands complete ones on.
func (a *Analyzer) psi(p *PID, b []byte, pusi bool) {
	if pusi {
		if len(b) < 1 {
			return
		}
		ptr := int(b[0])
		if 1+ptr > len(b) {
			return
		}
		// The bytes before the pointer finish the previous section.
		if p.section != nil && ptr > 0 {
			a.appendSection(p, b[1:1+ptr])
		}
		b = b[1+ptr:]
		p.section, p.sectLeft = nil, 0
		// Several short sections can share one packet.
		for len(b) >= 3 && b[0] != 0xff {
			l := 3 + (int(b[1]&0x0f)<<8 | int(b[2]))
			if l <= len(b) {
				a.section(p, b[:l])
				b = b[l:]
				continue
			}
			p.section = append([]byte(nil), b...)
			p.sectLeft = l - len(b)
			return
		}
		return
	}
	if p.section != nil {
		a.appendSection(p, b)
	}
}

func (a *Analyzer) appendSection(p *PID, b []byte) {
	if len(b) > p.sectLeft {
		b = b[:p.sectLeft]
	}
	p.section = append(p.section, b...)
	p.sectLeft -= len(b)
	if p.sectLeft == 0 {
		a.section(p, p.section)
		p.section = nil
	}
}

func (a *Analyzer) section(p *PID, s []byte) {
	if len(s) < 12 || s[1]&0x80 == 0 || CRC32(s) != 0 {
		return // not a long-form section, or damaged
	}
	switch {
	case p.PID == patPID && s[0] == 0x00:
		a.pat(s)
	case p.Kind == "PMT" && s[0] == 0x02:
		a.pmt(p, s)
	case p.PID == sdtPID && s[0] == 0x42: // SDT, actual transport stream
		a.sdt(s)
	}
}

func (a *Analyzer) pat(s []byte) {
	a.TSID = int(s[3])<<8 | int(s[4])
	body := s[8 : len(s)-4]
	for i := 0; i+4 <= len(body); i += 4 {
		prog := uint16(body[i])<<8 | uint16(body[i+1])
		pid := uint16(body[i+2]&0x1f)<<8 | uint16(body[i+3])
		if prog == 0 {
			continue // network PID
		}
		a.pmtPIDs[pid] = prog
		sv := a.service(prog)
		sv.PMTPID = pid
		pp := a.pid(pid)
		pp.Kind, pp.Program = "PMT", prog
	}
}

func (a *Analyzer) service(prog uint16) *Service {
	sv := a.services[prog]
	if sv == nil {
		sv = &Service{Program: prog}
		a.services[prog] = sv
	}
	return sv
}

func (a *Analyzer) pmt(p *PID, s []byte) {
	prog := uint16(s[3])<<8 | uint16(s[4])
	sv := a.service(prog)
	sv.PCRPID = uint16(s[8]&0x1f)<<8 | uint16(s[9])
	pil := int(s[10]&0x0f)<<8 | int(s[11])
	body := s[12 : len(s)-4]
	if pil > len(body) {
		return
	}
	body = body[pil:]
	for len(body) >= 5 {
		st := body[0]
		epid := uint16(body[1]&0x1f)<<8 | uint16(body[2])
		eil := int(body[3]&0x0f)<<8 | int(body[4])
		if 5+eil > len(body) {
			return
		}
		desc := body[5 : 5+eil]
		body = body[5+eil:]

		e := a.pid(epid)
		e.Program = prog
		e.StreamType = st
		e.Kind = streamKind(st, desc)
		e.Lang = language(desc)
	}
}

func (a *Analyzer) sdt(s []byte) {
	body := s[11 : len(s)-4]
	for len(body) >= 5 {
		sid := uint16(body[0])<<8 | uint16(body[1])
		dl := int(body[3]&0x0f)<<8 | int(body[4])
		if 5+dl > len(body) {
			return
		}
		desc := body[5 : 5+dl]
		body = body[5+dl:]
		for len(desc) >= 2 {
			tag, l := desc[0], int(desc[1])
			if 2+l > len(desc) {
				break
			}
			d := desc[2 : 2+l]
			desc = desc[2+l:]
			if tag != 0x48 || len(d) < 2 { // service_descriptor
				continue
			}
			sv := a.service(sid)
			sv.Type = serviceType(d[0])
			pl := int(d[1])
			if 2+pl >= len(d) {
				continue
			}
			sv.Provider = dvbString(d[2 : 2+pl])
			nl := int(d[2+pl])
			if 3+pl+nl <= len(d) {
				sv.Name = dvbString(d[3+pl : 3+pl+nl])
			}
		}
	}
}

// Services lists the programmes seen, in programme-number order.
func (a *Analyzer) Services() []Service {
	out := make([]Service, 0, len(a.services))
	for _, s := range a.services {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Program < out[j].Program })
	return out
}

// PIDs lists the PIDs seen, in PID order.
func (a *Analyzer) PIDs() []*PID {
	out := make([]*PID, 0, len(a.pids))
	for _, p := range a.pids {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// ServiceName is the first named programme, for labelling the stream.
func (a *Analyzer) ServiceName() string {
	for _, s := range a.Services() {
		if s.Name != "" {
			return s.Name
		}
	}
	return ""
}

// VideoSummary describes the first video PID, e.g. "H.264 1920×1080i".
func (a *Analyzer) VideoSummary() string {
	for _, p := range a.PIDs() {
		if strings.Contains(p.Kind, "video") {
			if p.Detail != "" {
				return strings.TrimSuffix(p.Kind, " video") + " " + p.Detail
			}
			return p.Kind
		}
	}
	return ""
}

func streamKind(st uint8, desc []byte) string {
	switch st {
	case 0x01:
		return "MPEG-1 video"
	case 0x02:
		return "MPEG-2 video"
	case 0x03:
		return "MPEG-1 audio"
	case 0x04:
		return "MPEG-2 audio"
	case 0x05:
		return "Private sections"
	case 0x0b:
		return "DSM-CC"
	case 0x0f:
		return "AAC audio"
	case 0x11:
		return "AAC-LATM audio"
	case 0x15:
		return "Metadata"
	case 0x1b:
		return "H.264 video"
	case 0x24:
		return "HEVC video"
	case 0x81:
		return "AC-3 audio"
	case 0x86:
		return "SCTE-35 cues"
	case 0x87:
		return "E-AC-3 audio"
	case 0x06:
		for len(desc) >= 2 {
			tag, l := desc[0], int(desc[1])
			switch tag {
			case 0x6a:
				return "AC-3 audio"
			case 0x7a:
				return "E-AC-3 audio"
			case 0x7c:
				return "AAC audio"
			case 0x59:
				return "DVB subtitles"
			case 0x56:
				return "Teletext"
			}
			if 2+l > len(desc) {
				break
			}
			desc = desc[2+l:]
		}
		return "Private data"
	}
	return fmt.Sprintf("Stream type 0x%02x", st)
}

func language(desc []byte) string {
	for len(desc) >= 2 {
		tag, l := desc[0], int(desc[1])
		if 2+l > len(desc) {
			return ""
		}
		d := desc[2 : 2+l]
		switch tag {
		case 0x0a, 0x59, 0x56: // ISO 639, subtitling, teletext all start with a code
			if len(d) >= 3 {
				return string(d[:3])
			}
		}
		desc = desc[2+l:]
	}
	return ""
}

func serviceType(t uint8) string {
	switch t {
	case 0x01:
		return "SD TV"
	case 0x02:
		return "Radio"
	case 0x11, 0x19, 0x1f:
		return "HD TV"
	case 0x16:
		return "SD TV"
	case 0x0a:
		return "Radio"
	case 0x0c:
		return "Data"
	}
	return fmt.Sprintf("type 0x%02x", t)
}

// dvbString reads a DVB text field. A first byte below 0x20 names a character
// table; the common ones are Latin variants, which read acceptably as Latin-1,
// and 0x15 is UTF-8.
func dvbString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	utf8 := false
	switch {
	case b[0] == 0x10 && len(b) >= 3:
		b = b[3:]
	case b[0] == 0x15:
		utf8, b = true, b[1:]
	case b[0] < 0x20:
		b = b[1:]
	}
	var sb strings.Builder
	if utf8 {
		for _, r := range string(b) {
			if r >= 0x20 && !(r >= 0x80 && r < 0xa0) {
				sb.WriteRune(r)
			}
		}
	} else {
		for _, c := range b {
			if c >= 0x20 && !(c >= 0x80 && c < 0xa0) { // drop DVB control codes
				sb.WriteRune(rune(c))
			}
		}
	}
	return strings.TrimSpace(sb.String())
}
