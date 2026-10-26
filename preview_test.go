//go:build !windows

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andreacoppini/packhound/internal/monitor"
	"github.com/andreacoppini/packhound/internal/mpegts"
	"github.com/andreacoppini/packhound/internal/pkt"
)

// fakeFFmpeg stands in for the encoder: it writes a playlist where the real
// one would, and reads its input until it ends.
func fakeFFmpeg(t *testing.T) string {
	script := filepath.Join(t.TempDir(), "ffmpeg")
	os.WriteFile(script, []byte(`#!/bin/sh
for a in "$@"; do out="$a"; done
printf '#EXTM3U\n#EXT-X-MAP:URI="init.mp4"\n#EXTINF:2.0,\nindex0.m4s\n' > "$out"
echo seg > "$(dirname "$out")/index0.m4s"
cat > /dev/null
`), 0o755)
	return script
}

// channels makes a monitor with n H.264 channels with audio, 239.3.1.1..n.
func channels(n int) *monitor.Monitor {
	m := monitor.New(monitor.DefaultConfig())
	t0 := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	for i := 1; i <= n; i++ {
		mux := mpegts.NewMuxer()
		var ps [][]byte
		ps = append(ps, mux.Section(0, mpegts.PAT(1, 1, 0x100))...)
		ps = append(ps, mux.Section(0x100, mpegts.PMT(1, 0x101, []mpegts.ES{{Type: 0x1b, PID: 0x101}, {Type: 0x03, PID: 0x102}}))...)
		ps = append(ps, mux.PES(0x102, 0xc0, make([]byte, 300))...)
		for _, p := range ps {
			m.Ingest(&pkt.Packet{Time: t0, Src: netip.MustParseAddr("10.7.0.15"), Dst: netip.AddrFrom4([4]byte{239, 3, 1, byte(i)}),
				Proto: pkt.ProtoUDP, SrcPort: 5000, DstPort: 5701, IPLen: 216, Payload: p})
		}
	}
	m.Tick(t0.Add(time.Second))
	return m
}

func TestPreviews(t *testing.T) {
	m := channels(3)
	ps := newPreviews(m, fakeFFmpeg(t), t.TempDir(), 2)
	get := func(path string) (int, string) {
		w := httptest.NewRecorder()
		ps.serve(w, httptest.NewRequest(http.MethodGet, path, nil), "/api/v1/live", "token=abc")
		b, _ := io.ReadAll(w.Result().Body)
		return w.Code, string(b)
	}
	// Two viewers of one channel share one encoder.
	for i := 0; i < 2; i++ {
		code, body := get("/api/v1/live/239.3.1.1:5701/low/index.m3u8")
		if code != 200 || !strings.Contains(body, "index0.m4s?token=abc") || !strings.Contains(body, `init.mp4?token=abc"`) {
			t.Fatalf("playlist %d: %s", code, body)
		}
	}
	if len(ps.live) != 1 {
		t.Fatalf("%d encoders for one channel", len(ps.live))
	}
	if code, body := get("/api/v1/live/239.3.1.1:5701/low/index0.m4s"); code != 200 || body != "seg\n" {
		t.Errorf("segment %d %q", code, body)
	}
	if code, _ := get("/api/v1/live/239.3.1.1:5701/low/..%2Fx.m4s"); code != 404 {
		t.Errorf("path outside the preview: %d", code)
	}
	// The cap: a second channel fits, a third does not.
	if code, _ := get("/api/v1/live/239.3.1.2:5701/low/index.m3u8"); code != 200 {
		t.Errorf("second channel: %d", code)
	}
	if code, body := get("/api/v1/live/239.3.1.3:5701/low/index.m3u8"); code != 503 || !strings.Contains(body, "2 previews") {
		t.Errorf("past the cap: %d %s", code, body)
	}
	// Nobody watching: they stop, and their segments go.
	ps.mu.Lock()
	var dirs []string
	for _, p := range ps.live {
		p.watched = time.Now().Add(-time.Hour)
		dirs = append(dirs, p.dir)
	}
	ps.mu.Unlock()
	ps.reapOnce()
	if len(ps.live) != 0 {
		t.Fatalf("%d still running", len(ps.live))
	}
	deadline := time.Now().Add(5 * time.Second)
	for _, d := range dirs {
		for {
			if _, err := os.Stat(d); os.IsNotExist(err) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s not removed", d)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}
