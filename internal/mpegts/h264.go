package mpegts

import (
	"bytes"
	"fmt"
)

// h264Scan looks for a sequence parameter set in an H.264 elementary stream
// to read the picture size from. It holds at most a few kilobytes and gives up
// on a PES packet once that is full; encoders repeat the SPS at every
// keyframe, so the next one gets another chance.
type h264Scan struct {
	buf    []byte
	result string
}

const h264ScanMax = 8 << 10

func (h *h264Scan) feed(b []byte, pusi bool) {
	if pusi {
		h.buf = h.buf[:0]
		// Skip the PES header: 00 00 01, stream id, length, two flag bytes,
		// header data length.
		if len(b) < 9 || b[0] != 0 || b[1] != 0 || b[2] != 1 {
			return
		}
		hl := 9 + int(b[8])
		if hl > len(b) {
			return
		}
		b = b[hl:]
	} else if len(h.buf) == 0 {
		return // joined mid-PES; wait for the next start
	}
	if len(h.buf)+len(b) > h264ScanMax {
		return
	}
	h.buf = append(h.buf, b...)
	if s, ok := findSPS(h.buf); ok {
		h.result = s
	}
}

// findSPS finds a complete SPS NAL unit in b and describes it.
func findSPS(b []byte) (string, bool) {
	for i := 0; i+3 < len(b); i++ {
		if b[i] != 0 || b[i+1] != 0 || b[i+2] != 1 {
			continue
		}
		if b[i+3]&0x1f != 7 {
			continue
		}
		rest := b[i+4:]
		// The SPS runs to the next start code, which must have arrived for
		// the unit to be complete.
		end := bytes.Index(rest, []byte{0, 0, 1})
		if end < 0 {
			return "", false
		}
		w, h, interlaced, ok := ParseSPS(rest[:end])
		if !ok {
			return "", false
		}
		scan := "p"
		if interlaced {
			scan = "i"
		}
		return fmt.Sprintf("%d×%d%s", w, h, scan), true
	}
	return "", false
}

// ParseSPS reads the picture size from an H.264 SPS, given without its NAL
// header byte.
func ParseSPS(nal []byte) (width, height int, interlaced, ok bool) {
	r := bitReader{b: unescape(nal)}
	profile := r.u(8)
	r.u(16) // constraint flags, level
	r.ue()  // seq_parameter_set_id
	chroma := uint32(1)
	switch profile {
	case 100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135:
		chroma = r.ue()
		if chroma == 3 {
			r.u(1)
		}
		r.ue()
		r.ue()
		r.u(1)
		if r.u(1) == 1 { // seq_scaling_matrix_present_flag
			n := 8
			if chroma == 3 {
				n = 12
			}
			for i := 0; i < n; i++ {
				if r.u(1) == 1 {
					size := 16
					if i >= 6 {
						size = 64
					}
					last, next := int32(8), int32(8)
					for j := 0; j < size; j++ {
						if next != 0 {
							next = (last + r.se() + 256) % 256
						}
						if next != 0 {
							last = next
						}
					}
				}
			}
		}
	}
	r.ue() // log2_max_frame_num_minus4
	switch r.ue() {
	case 0:
		r.ue()
	case 1:
		r.u(1)
		r.se()
		r.se()
		n := r.ue()
		if n > 255 {
			return 0, 0, false, false
		}
		for i := uint32(0); i < n; i++ {
			r.se()
		}
	}
	r.ue() // max_num_ref_frames
	r.u(1)
	wmbs := int(r.ue()) + 1
	hmap := int(r.ue()) + 1
	frameOnly := int(r.u(1))
	if frameOnly == 0 {
		r.u(1)
	}
	r.u(1)
	var cl, cr, ct, cb int
	if r.u(1) == 1 {
		cl, cr, ct, cb = int(r.ue()), int(r.ue()), int(r.ue()), int(r.ue())
	}
	if r.err {
		return 0, 0, false, false
	}
	subW, subH := 2, 2
	switch chroma {
	case 0:
		subW, subH = 1, 1
	case 2:
		subH = 1
	case 3:
		subW, subH = 1, 1
	}
	cropX := subW
	cropY := subH * (2 - frameOnly)
	width = wmbs*16 - cropX*(cl+cr)
	height = (2-frameOnly)*hmap*16 - cropY*(ct+cb)
	if width <= 0 || height <= 0 || width > 16384 || height > 16384 {
		return 0, 0, false, false
	}
	return width, height, frameOnly == 0, true
}

// unescape removes emulation-prevention bytes (00 00 03 -> 00 00).
func unescape(b []byte) []byte {
	out := make([]byte, 0, len(b))
	zeros := 0
	for _, c := range b {
		if zeros >= 2 && c == 3 {
			zeros = 0
			continue
		}
		if c == 0 {
			zeros++
		} else {
			zeros = 0
		}
		out = append(out, c)
	}
	return out
}

type bitReader struct {
	b   []byte
	pos int
	err bool
}

func (r *bitReader) u(n int) uint32 {
	var v uint32
	for i := 0; i < n; i++ {
		if r.pos >= len(r.b)*8 {
			r.err = true
			return 0
		}
		bit := (r.b[r.pos/8] >> (7 - r.pos%8)) & 1
		v = v<<1 | uint32(bit)
		r.pos++
	}
	return v
}

func (r *bitReader) ue() uint32 {
	zeros := 0
	for r.u(1) == 0 {
		if r.err || zeros > 31 {
			r.err = true
			return 0
		}
		zeros++
	}
	return (1<<zeros - 1) + r.u(zeros)
}

func (r *bitReader) se() int32 {
	v := r.ue()
	if v&1 == 1 {
		return int32((v + 1) / 2)
	}
	return -int32(v / 2)
}
