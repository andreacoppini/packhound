package monitor

import (
	"net/netip"
	"testing"
	"time"
)

// TestTap delivers each datagram's bytes as a copy, and drops rather than
// blocking when the reader stops reading.
func TestTap(t *testing.T) {
	m := New(DefaultConfig())
	dg := make([]byte, 7*188)
	for i := 0; i < 7; i++ {
		dg[i*188] = 0x47
	}
	m.Ingest(udpPacket(t0, "10.7.0.15", "239.3.1.2", 5000, 5701, dg))
	key := Key{Dst: netip.MustParseAddr("239.3.1.2"), Proto: 17, Port: 5701}.String()
	tap, err := m.Tap(key)
	if err != nil {
		t.Fatal(err)
	}
	m.Ingest(udpPacket(t0, "10.7.0.15", "239.3.1.2", 5000, 5701, dg))
	dg[1] = 0xaa // the capture buffer is reused
	got := <-tap.C
	if len(got) != len(dg) || got[1] != 0 {
		t.Fatalf("got %d bytes, byte 1 = %#x: not a copy", len(got), got[1])
	}
	done := make(chan bool)
	go func() {
		for i := 0; i < tapDepth+10; i++ {
			m.Ingest(udpPacket(t0.Add(time.Millisecond), "10.7.0.15", "239.3.1.2", 5000, 5701, dg))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a stalled tap held up ingest")
	}
	if tap.Dropped() != 10 {
		t.Errorf("dropped %d, want 10", tap.Dropped())
	}
	tap.Close()
	tap.Close()
	m.Ingest(udpPacket(t0, "10.7.0.15", "239.3.1.2", 5000, 5701, dg)) // after close: no send on a closed channel
	if _, err := m.Tap("239.9.9.9|17|1"); err == nil {
		t.Error("tapped a stream that does not exist")
	}
}
