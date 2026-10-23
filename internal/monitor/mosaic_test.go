package monitor

import (
	"net/netip"
	"testing"
	"time"

	"github.com/andreacoppini/packhound/internal/mpegts"
)

// TestChannels lists a transport stream for the mosaic with its video's
// decoder and whether audio is arriving, and grabs its key picture.
func TestChannels(t *testing.T) {
	m := New(DefaultConfig())
	mux := mpegts.NewMuxer()
	var pkts [][]byte
	pkts = append(pkts, mux.Section(0, mpegts.PAT(1, 1, 0x100))...)
	pkts = append(pkts, mux.Section(0x100, mpegts.PMT(1, 0x101, []mpegts.ES{{Type: 0x1b, PID: 0x101}, {Type: 0x03, PID: 0x102}}))...)
	at := t0
	send := func(ps [][]byte) {
		for _, p := range ps {
			m.Ingest(udpPacket(at, "10.7.0.15", "239.3.1.1", 5000, 5701, p))
			at = at.Add(time.Millisecond)
		}
	}
	send(pkts)
	key := Key{Dst: netip.MustParseAddr("239.3.1.1"), Proto: 17, Port: 5701}.String()
	if !m.StartGrab(key) {
		t.Fatal("StartGrab: no video")
	}
	send(mux.PES(0x102, 0xc0, make([]byte, 400)))
	send(mux.PES(0x101, 0xe0, append([]byte{0, 0, 0, 1}, mpegts.SPS(1920, 1080, false)...)))
	send(mux.PES(0x101, 0xe0, []byte{0, 0, 0, 1, 5, 1, 2, 3}))
	send(mux.PES(0x101, 0xe0, []byte{0, 0, 0, 1, 1, 1, 2, 3}))
	m.Tick(at.Add(time.Second))

	chans := m.Channels()
	if len(chans) != 1 {
		t.Fatalf("%d channels, want 1", len(chans))
	}
	c := chans[0]
	if c.Group != "239.3.1.1:5701" || c.Codec != "h264" || !c.HasAudio || !c.Audio || c.Scrambled {
		t.Errorf("channel: %+v", c)
	}
	if _, codec, ok := m.Grabbed(key); !ok || codec != "h264" {
		t.Errorf("Grabbed: ok %v, codec %q", ok, codec)
	}
}
