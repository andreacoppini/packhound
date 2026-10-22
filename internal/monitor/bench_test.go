package monitor

import (
	"net/netip"
	"testing"
	"time"

	"github.com/andreacoppini/packhound/internal/mpegts"
	"github.com/andreacoppini/packhound/internal/pkt"
)

// BenchmarkIngestIPTV feeds 80 MPEG-TS channels, seven TS packets per
// datagram, as a head-end sends them.
func BenchmarkIngestIPTV(b *testing.B) {
	const streams = 80
	m := New(DefaultConfig())
	muxes := make([]*mpegts.Muxer, streams)
	for i := range muxes {
		muxes[i] = mpegts.NewMuxer()
	}
	// Pre-built datagrams per stream, cycled.
	var dgs [streams][][]byte
	for s := 0; s < streams; s++ {
		var all []byte
		all = append(all, muxes[s].Section(0, mpegts.PAT(1, 1, 0x100))[0]...)
		for len(all) < 64*7*188 {
			for _, p := range muxes[s].PES(0x101, 0xe0, make([]byte, 1500)) {
				all = append(all, p...)
			}
		}
		for i := 0; i+7*188 <= len(all); i += 7 * 188 {
			dgs[s] = append(dgs[s], all[i:i+7*188])
		}
	}
	src := netip.MustParseAddr("10.7.0.15")
	now := time.Unix(1_800_000_000, 0)
	b.SetBytes(7 * 188)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := i % streams
		d := dgs[s][(i/streams)%len(dgs[s])]
		now = now.Add(30 * time.Microsecond)
		m.Ingest(&pkt.Packet{Time: now, Src: src, Dst: netip.AddrFrom4([4]byte{239, 3, 1, byte(s)}), Proto: pkt.ProtoUDP, DstPort: 5701, IPLen: 28 + len(d), Payload: d})
		if i%30000 == 0 {
			m.Tick(now)
		}
	}
}
