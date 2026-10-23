package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andreacoppini/packhound/internal/monitor"
	"github.com/andreacoppini/packhound/internal/pkt"
)

// tsDatagram is seven TS packets on PID 0x100, counters continuing from cc.
func tsDatagram(cc *byte) []byte {
	b := make([]byte, 0, 7*188)
	for i := 0; i < 7; i++ {
		p := make([]byte, 188)
		p[0], p[1], p[2], p[3] = 0x47, 0x01, 0x00, 0x10|*cc
		*cc = (*cc + 1) & 0x0f
		b = append(b, p...)
	}
	return b
}

// TestReadCapture replays a capture in which one of two channels stops for
// ten seconds: the alerts carry the capture's times, and the rates are
// averages over the file.
func TestReadCapture(t *testing.T) {
	t0 := time.Date(2026, 10, 23, 14, 0, 0, 0, time.UTC)
	var file bytes.Buffer
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], 65535)
	binary.LittleEndian.PutUint32(h[20:], pkt.LinkEthernet)
	file.Write(h)
	var cc [2]byte
	for ms := 0; ms < 30000; ms += 10 {
		for ch := 0; ch < 2; ch++ {
			if ch == 1 && ms >= 10000 && ms < 20000 {
				continue // channel 2 stops for ten seconds
			}
			f := pkt.Frame(pkt.Spec{Src: netip.MustParseAddr("10.7.0.15"), Dst: netip.AddrFrom4([4]byte{239, 3, 1, byte(ch + 1)}),
				SrcPort: 5000, DstPort: 5701, Payload: tsDatagram(&cc[ch])})
			ts := t0.Add(time.Duration(ms) * time.Millisecond)
			var r [16]byte
			binary.LittleEndian.PutUint32(r[0:], uint32(ts.Unix()))
			binary.LittleEndian.PutUint32(r[4:], uint32(ts.Nanosecond()/1000))
			binary.LittleEndian.PutUint32(r[8:], uint32(len(f)))
			binary.LittleEndian.PutUint32(r[12:], uint32(len(f)))
			file.Write(r[:])
			file.Write(f)
		}
	}

	v := newFileView("test.pcap", monitor.DefaultConfig(), "")
	var mu sync.Mutex
	if err := readCapture(&file, v, &mu); err != nil {
		t.Fatal(err)
	}
	if v.Packets != 5000 || !v.First.Equal(t0) {
		t.Errorf("%d packets from %v", v.Packets, v.First)
	}
	snap := v.mon.Snapshot("", 60)
	var stopped, back time.Time
	for _, a := range snap.Alerts {
		switch {
		case strings.HasPrefix(a.Message, "Stopped"):
			stopped = a.Time
		case strings.HasPrefix(a.Message, "Back"):
			back = a.Time
		}
	}
	if d := stopped.Sub(t0); d < 15*time.Second || d > 17*time.Second {
		t.Errorf("stopped alert at +%v, want about +16s", d)
	}
	if d := back.Sub(t0); d < 20*time.Second || d > 22*time.Second {
		t.Errorf("back alert at +%v, want about +21s", d)
	}
	for _, r := range snap.Rows {
		if r.Group != "239.3.1.1:5701" {
			continue
		}
		want := float64((7*188+28)*8*3000) / 29.99 // 3000 IP datagrams in 29.99 s
		if r.BPS < want*0.99 || r.BPS > want*1.01 || r.Status != monitor.Receiving || r.Errors != "0" {
			t.Errorf("steady channel: %.0f b/s (want %.0f), %s, errors %s", r.BPS, want, r.Status, r.Errors)
		}
	}
}
