package monitor

import (
	"errors"
	"sync/atomic"

	"github.com/andreacoppini/packhound/internal/pkt"
)

// A Tap hands a channel's transport stream to a reader outside the monitor,
// a datagram's worth at a time, as it arrives: what a live preview encodes.
// It never holds up capture: when the reader falls behind, datagrams are
// dropped and counted.
type Tap struct {
	C       <-chan []byte
	c       chan []byte
	key     Key
	m       *Monitor
	dropped atomic.Uint64
	closed  bool // guarded by m.mu
}

// tapDepth is how many datagrams a tap holds for a slow reader: a couple of
// seconds of a busy HD channel.
const tapDepth = 2048

// Tap opens a tap on the transport stream with the given key.
func (m *Monitor) Tap(key string) (*Tap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.streams {
		if k.String() != key {
			continue
		}
		if s.ts() == nil {
			return nil, errors.New("not a transport stream")
		}
		c := make(chan []byte, tapDepth)
		t := &Tap{C: c, c: c, key: k, m: m}
		if m.taps == nil {
			m.taps = map[Key][]*Tap{}
		}
		m.taps[k] = append(m.taps[k], t)
		return t, nil
	}
	return nil, errors.New("no such stream")
}

// Close stops the tap and closes its channel.
func (t *Tap) Close() {
	m := t.m
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	taps := m.taps[t.key]
	for i, x := range taps {
		if x == t {
			taps = append(taps[:i], taps[i+1:]...)
			break
		}
	}
	if len(taps) == 0 {
		delete(m.taps, t.key)
	} else {
		m.taps[t.key] = taps
	}
	close(t.c)
}

// Dropped counts the datagrams the reader was too slow to take.
func (t *Tap) Dropped() uint64 { return t.dropped.Load() }

// feedTaps copies a datagram of s to its taps. The payload is the capture
// buffer's, so each tap gets its own copy; RTP is unwrapped to the TS.
func (m *Monitor) feedTaps(s *Stream, p *pkt.Packet) {
	taps := m.taps[s.key]
	if len(taps) == 0 || p.Frag != pkt.Whole {
		return
	}
	b := p.Payload
	if _, ok := s.dec.(*rtpDec); ok {
		h, ok := rtpHeader(b)
		if !ok {
			return
		}
		b = h.payload
	}
	for _, t := range taps {
		select {
		case t.c <- append([]byte(nil), b...):
		default:
			t.dropped.Add(1)
		}
	}
}
