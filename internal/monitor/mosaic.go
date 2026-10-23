package monitor

import (
	"sort"
	"strings"
)

// Channel is a transport stream as the mosaic shows it.
type Channel struct {
	Key              string  `json:"key"`
	Group            string  `json:"group"`
	Name             string  `json:"name"`
	Sender           string  `json:"sender"`
	SenderName       string  `json:"senderName,omitempty"`
	BPS              float64 `json:"bps"`
	Status           Status  `json:"status"`
	StatusLevel      string  `json:"statusLevel"`
	Reason           string  `json:"reason,omitempty"`
	Errors           string  `json:"errors"`
	ErrLevel         string  `json:"errLevel"`
	ErrorsLastMinute uint64  `json:"errorsLastMinute"`
	Video            string  `json:"video,omitempty"` // "H.264 1920×1080i"
	// Codec is the decoder the video needs, "" when there is none here.
	Codec     string `json:"-"`
	Scrambled bool   `json:"scrambled"` // the video is scrambled
	HasAudio  bool   `json:"hasAudio"`
	// Audio is true while audio packets arrive in the clear. It says the
	// audio is there, not that it is not silent.
	Audio bool `json:"audio"`
}

// ts is the stream's transport stream, when it carries one.
func (s *Stream) ts() *tsDec {
	switch d := s.dec.(type) {
	case *tsDec:
		return d
	case *rtpDec:
		return d.ts
	}
	return nil
}

// Channels lists the transport streams, in group order.
func (m *Monitor) Channels() []Channel {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]Key, 0, len(m.streams))
	for k, s := range m.streams {
		if s.ts() != nil {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if c := keys[i].Dst.Compare(keys[j].Dst); c != 0 {
			return c < 0
		}
		return keys[i].Port < keys[j].Port
	})
	out := make([]Channel, 0, len(keys))
	for _, k := range keys {
		s := m.streams[k]
		t := s.ts()
		r := s.row()
		c := Channel{Key: r.Key, Group: r.Group, Name: r.Name, Sender: r.Sender, SenderName: r.SenderName, BPS: r.BPS,
			Status: r.Status, StatusLevel: r.StatusLevel, Reason: r.Reason, Errors: r.Errors, ErrLevel: r.ErrLevel,
			ErrorsLastMinute: r.ErrorsLastMinute, Video: t.a.VideoSummary()}
		if p, codec := t.a.VideoPID(); p != nil {
			c.Codec, c.Scrambled = codec, p.Scrambled
		} else {
			for _, p := range t.a.PIDs() {
				if strings.Contains(p.Kind, "video") && p.Scrambled {
					c.Scrambled = true
				}
			}
		}
		c.HasAudio, c.Audio = t.a.AudioFlowing()
		if s.status == Lost {
			c.Audio = false
		}
		out = append(out, c)
	}
	return out
}

func (m *Monitor) tsByKey(key string) *tsDec {
	for k, s := range m.streams {
		if k.String() == key {
			return s.ts()
		}
	}
	return nil
}

// StartGrab starts collecting a key picture from a channel's video, for a
// thumbnail. It returns false when the channel has no video to grab.
func (m *Monitor) StartGrab(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.tsByKey(key)
	return t != nil && t.a.StartGrab()
}

// Grabbed returns a finished grab's elementary stream and the decoder it
// needs, ending the grab.
func (m *Monitor) Grabbed(key string) (es []byte, codec string, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t := m.tsByKey(key); t != nil {
		return t.a.Grabbed()
	}
	return nil, "", false
}

// StopGrab abandons a grab.
func (m *Monitor) StopGrab(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t := m.tsByKey(key); t != nil {
		t.a.StopGrab()
	}
}
