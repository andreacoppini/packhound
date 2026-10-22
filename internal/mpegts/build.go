package mpegts

// Building transport streams: enough to make realistic traffic for the demo
// source and the tests, not a multiplexer.

var crcTable = func() (t [256]uint32) {
	for i := range t {
		c := uint32(i) << 24
		for j := 0; j < 8; j++ {
			if c&0x80000000 != 0 {
				c = c<<1 ^ 0x04c11db7
			} else {
				c <<= 1
			}
		}
		t[i] = c
	}
	return
}()

// CRC32 is the MPEG-2 CRC. Run over a whole section including its CRC field
// it returns zero when the section is intact.
func CRC32(b []byte) uint32 {
	c := uint32(0xffffffff)
	for _, x := range b {
		c = c<<8 ^ crcTable[byte(c>>24)^x]
	}
	return c
}

// section wraps body in a long-form PSI section header and CRC.
func section(tableID uint8, ext uint16, body []byte) []byte {
	l := 5 + len(body) + 4
	s := []byte{tableID, 0xb0 | byte(l>>8), byte(l), byte(ext >> 8), byte(ext), 0xc1, 0, 0}
	s = append(s, body...)
	c := CRC32(s)
	return append(s, byte(c>>24), byte(c>>16), byte(c>>8), byte(c))
}

// PAT builds a programme association table naming one programme.
func PAT(tsid, program, pmtPID uint16) []byte {
	return section(0x00, tsid, []byte{byte(program >> 8), byte(program), 0xe0 | byte(pmtPID>>8), byte(pmtPID)})
}

// ES is an elementary stream for PMT.
type ES struct {
	Type uint8
	PID  uint16
	Lang string // optional ISO 639 code
	Desc []byte // further descriptors
}

// PMT builds a programme map table.
func PMT(program, pcrPID uint16, es []ES) []byte {
	body := []byte{0xe0 | byte(pcrPID>>8), byte(pcrPID), 0xf0, 0}
	for _, e := range es {
		d := append([]byte(nil), e.Desc...)
		if e.Lang != "" {
			d = append(d, 0x0a, 4, e.Lang[0], e.Lang[1], e.Lang[2], 0)
		}
		body = append(body, e.Type, 0xe0|byte(e.PID>>8), byte(e.PID), 0xf0|byte(len(d)>>8), byte(len(d)))
		body = append(body, d...)
	}
	return section(0x02, program, body)
}

// SDT builds a service description table naming one service.
func SDT(tsid, onid, program uint16, svcType uint8, provider, name string) []byte {
	d := []byte{0x48, byte(3 + len(provider) + len(name)), svcType, byte(len(provider))}
	d = append(d, provider...)
	d = append(d, byte(len(name)))
	d = append(d, name...)
	body := []byte{byte(onid >> 8), byte(onid), 0xff,
		byte(program >> 8), byte(program), 0xfc, 0x80 | byte(len(d)>>8), byte(len(d))}
	body = append(body, d...)
	return section(0x42, tsid, body)
}

// Muxer packetises payloads onto PIDs, keeping each PID's continuity counter.
type Muxer struct {
	cc map[uint16]uint8
	// SkipCC, when set, is asked before every packet; returning true makes
	// that PID's counter jump, which a receiver sees as a lost packet.
	SkipCC func(pid uint16) bool
}

func NewMuxer() *Muxer { return &Muxer{cc: map[uint16]uint8{}} }

// Section puts a PSI section on pid, with a pointer field, padded to whole
// packets.
func (m *Muxer) Section(pid uint16, s []byte) [][]byte {
	return m.packets(pid, append([]byte{0}, s...), 0xff)
}

// PES puts an elementary-stream payload on pid behind a minimal PES header.
func (m *Muxer) PES(pid uint16, streamID uint8, es []byte) [][]byte {
	h := []byte{0, 0, 1, streamID, 0, 0, 0x80, 0, 0}
	return m.packets(pid, append(h, es...), 0xff)
}

// AdaptationOnly is a packet on pid carrying only an adaptation field, as
// encoders send a PCR between video packets. With advance set, the counter
// moves on as it would for a payload packet, which is the non-compliant
// behaviour some encoders have.
func (m *Muxer) AdaptationOnly(pid uint16, advance bool) []byte {
	p := make([]byte, PacketSize)
	p[0], p[1], p[2] = SyncByte, byte(pid>>8)&0x1f, byte(pid)
	cc := (m.cc[pid] - 1) & 0x0f
	if advance {
		cc = m.cc[pid]
		m.cc[pid] = (cc + 1) & 0x0f
	}
	p[3] = 0x20 | cc
	p[4] = 183
	p[5] = 0x10 // PCR flag
	for i := 12; i < PacketSize; i++ {
		p[i] = 0xff
	}
	return p
}

// Null is one null packet.
func (m *Muxer) Null() []byte {
	p := make([]byte, PacketSize)
	p[0], p[1], p[2], p[3] = SyncByte, 0x1f, 0xff, 0x10
	for i := 4; i < len(p); i++ {
		p[i] = 0xff
	}
	return p
}

func (m *Muxer) packets(pid uint16, data []byte, fill byte) [][]byte {
	var out [][]byte
	first := true
	for len(data) > 0 {
		p := make([]byte, PacketSize)
		p[0] = SyncByte
		p[1] = byte(pid>>8) & 0x1f
		if first {
			p[1] |= 0x40
		}
		p[2] = byte(pid)
		cc := m.cc[pid]
		if m.SkipCC != nil && m.SkipCC(pid) {
			cc = (cc + 1) & 0x0f
		}
		p[3] = 0x10 | cc
		m.cc[pid] = (cc + 1) & 0x0f
		n := copy(p[4:], data)
		for i := 4 + n; i < PacketSize; i++ {
			p[i] = fill
		}
		data = data[n:]
		out = append(out, p)
		first = false
	}
	return out
}

// SPS builds an H.264 sequence parameter set NAL unit (header byte included)
// for a main-profile picture of the given size. Width and height must be
// multiples of 16, or of 32 in height when interlaced, apart from the 1080
// lines every HD encoder signals with cropping.
func SPS(width, height int, interlaced bool) []byte {
	var w bitWriter
	w.u(8, 77) // main profile
	w.u(8, 0)
	w.u(8, 40)
	w.ue(0) // sps id
	w.ue(0) // log2_max_frame_num_minus4
	w.ue(2) // poc type 2
	w.ue(1) // max_num_ref_frames
	w.u(1, 0)
	frameOnly := 1
	if interlaced {
		frameOnly = 0
	}
	mbH := 16 * (2 - frameOnly)
	codedH := (height + mbH - 1) / mbH * mbH
	w.ue(uint32(width/16 - 1))
	w.ue(uint32(codedH/mbH - 1))
	w.u(1, uint32(frameOnly))
	if frameOnly == 0 {
		w.u(1, 0)
	}
	w.u(1, 1) // direct_8x8_inference
	if crop := codedH - height; crop > 0 {
		w.u(1, 1)
		w.ue(0)
		w.ue(0)
		w.ue(0)
		w.ue(uint32(crop / (2 * (2 - frameOnly))))
	} else {
		w.u(1, 0)
	}
	w.u(1, 0) // no VUI
	w.u(1, 1) // stop bit
	return append([]byte{0x67}, w.bytes()...)
}

type bitWriter struct {
	b []byte
	n int
}

func (w *bitWriter) u(n int, v uint32) {
	for i := n - 1; i >= 0; i-- {
		if w.n%8 == 0 {
			w.b = append(w.b, 0)
		}
		if v>>i&1 == 1 {
			w.b[len(w.b)-1] |= 1 << (7 - w.n%8)
		}
		w.n++
	}
}

func (w *bitWriter) ue(v uint32) {
	v++
	n := 0
	for x := v; x > 1; x >>= 1 {
		n++
	}
	w.u(n, 0)
	w.u(n+1, v)
}

func (w *bitWriter) bytes() []byte { return w.b }
