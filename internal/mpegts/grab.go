package mpegts

import "strings"

// A grab collects one key picture of a programme's video, for a thumbnail:
// the first PES carrying a sequence header (where a decoder can start), plus
// the PES after it, which holds the second field of an interlaced picture
// sent as two. The video is not decoded here; the elementary stream is
// handed to a decoder.
type grab struct {
	pid   uint16
	codec string // "h264", "hevc" or "mpegvideo": ffmpeg's raw formats
	cur   []byte // payload of the PES being collected
	inPES bool
	key   []byte // the key PES, once found
	done  []byte
}

// A key picture with its sequence header is rarely over a megabyte even in
// UHD; anything bigger is not a picture worth waiting for.
const maxGrab = 4 << 20

// Codec names the decoder for a video stream type, "" when there is none.
func Codec(streamType uint8) string {
	switch streamType {
	case 0x1b:
		return "h264"
	case 0x24:
		return "hevc"
	case 0x01, 0x02:
		return "mpegvideo"
	}
	return ""
}

// VideoPID is the first video PID with a decoder, and that decoder's name.
func (a *Analyzer) VideoPID() (*PID, string) {
	for _, p := range a.PIDs() {
		if c := Codec(p.StreamType); c != "" && strings.Contains(p.Kind, "video") {
			return p, c
		}
	}
	return nil, ""
}

// ClearAudioPID is the first audio PID arriving in the clear, for a
// preview to play, or 0 when there is none.
func (a *Analyzer) ClearAudioPID() uint16 {
	for _, p := range a.PIDs() {
		if strings.Contains(p.Kind, "audio") && !p.Scrambled && p.Rate() > 0 {
			return p.PID
		}
	}
	return 0
}

// AudioFlowing reports whether the stream carries audio, and whether any of
// it is arriving in the clear.
func (a *Analyzer) AudioFlowing() (has, flowing bool) {
	for _, p := range a.pids {
		if strings.Contains(p.Kind, "audio") {
			has = true
			if !p.Scrambled && p.Rate() > 0 {
				flowing = true
			}
		}
	}
	return has, flowing
}

// StartGrab starts collecting a key picture. It returns false when there is
// no video to grab yet.
func (a *Analyzer) StartGrab() bool {
	p, codec := a.VideoPID()
	if p == nil {
		return false
	}
	a.grab = &grab{pid: p.PID, codec: codec}
	return true
}

// StopGrab abandons a grab.
func (a *Analyzer) StopGrab() { a.grab = nil }

// Grabbed returns the elementary stream of a finished grab and its codec,
// and ends the grab.
func (a *Analyzer) Grabbed() (es []byte, codec string, ok bool) {
	g := a.grab
	if g == nil || g.done == nil {
		return nil, "", false
	}
	a.grab = nil
	return g.done, g.codec, true
}

// Grabbing reports whether a grab is collecting.
func (a *Analyzer) Grabbing() bool { return a.grab != nil && a.grab.done == nil }

func (g *grab) packet(payload []byte, pusi bool) {
	if g.done != nil {
		return
	}
	if pusi {
		if g.inPES {
			g.endPES()
			if g.done != nil {
				return
			}
		}
		// PES header: start code, stream id, length, two flag bytes and the
		// header's own length; the elementary stream follows.
		if len(payload) < 9 || payload[0] != 0 || payload[1] != 0 || payload[2] != 1 {
			g.inPES = false
			return
		}
		h := 9 + int(payload[8])
		if h > len(payload) {
			g.inPES = false
			return
		}
		g.cur = append(g.cur[:0], payload[h:]...)
		g.inPES = true
		return
	}
	if g.inPES {
		if len(g.cur)+len(payload) > maxGrab {
			g.inPES, g.key = false, nil
			return
		}
		g.cur = append(g.cur, payload...)
	}
}

// endPES closes the PES collected so far: the key picture when it starts a
// sequence, and the end of the grab when it follows one.
func (g *grab) endPES() {
	g.inPES = false
	if g.key != nil {
		g.done = append(g.key, g.cur...)
		return
	}
	if startsSequence(g.cur, g.codec) {
		g.key = append([]byte(nil), g.cur...)
	}
}

// startsSequence reports whether an elementary-stream chunk carries the
// headers a decoder starts from, which encoders send with each key picture:
// the sequence parameter set in H.264, the video or sequence parameter set
// in HEVC, the sequence header in MPEG-2.
func startsSequence(b []byte, codec string) bool {
	for i := 0; i+3 < len(b); i++ {
		if b[i] != 0 || b[i+1] != 0 || b[i+2] != 1 {
			continue
		}
		c := b[i+3]
		switch codec {
		case "h264":
			if c&0x1f == 7 {
				return true
			}
		case "hevc":
			if t := (c >> 1) & 0x3f; t == 32 || t == 33 {
				return true
			}
		case "mpegvideo":
			if c == 0xb3 {
				return true
			}
		}
		i += 2
	}
	return false
}
