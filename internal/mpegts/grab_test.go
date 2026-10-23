package mpegts

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestGrab collects the key picture, the one carrying a sequence parameter
// set, and the picture after it, skipping what comes before.
func TestGrab(t *testing.T) {
	m := NewMuxer()
	a := NewAnalyzer()
	feed := func(ps [][]byte) {
		for _, p := range ps {
			a.Feed(p)
		}
	}
	feed(m.Section(0, PAT(1, 1, 0x100)))
	feed(m.Section(0x100, PMT(1, 0x101, []ES{{Type: 0x1b, PID: 0x101}, {Type: 0x03, PID: 0x102}})))
	if a.StartGrab() != true {
		t.Fatal("no video to grab")
	}
	nal := func(typ byte, n int) []byte { return append([]byte{0, 0, 0, 1, typ}, bytes.Repeat([]byte{0xab}, n)...) }
	feed(m.PES(0x101, 0xe0, nal(1, 500)))                                                     // a P picture: skipped
	feed(m.PES(0x101, 0xe0, append(append(nal(9, 1), 0, 0, 0, 1), SPS(1920, 1080, true)...))) // AUD, SPS ...
	feed(m.PES(0x101, 0xe0, nal(5, 2000)))                                                    // ... but that PES ended: not a picture yet
	if _, _, ok := a.Grabbed(); ok {
		t.Fatal("grab finished before the picture after the key one began")
	}
	feed(m.PES(0x101, 0xe0, nal(1, 300)))
	es, codec, ok := a.Grabbed()
	if !ok || codec != "h264" {
		t.Fatalf("grab: ok %v, codec %q", ok, codec)
	}
	if !bytes.HasPrefix(es, []byte{0, 0, 0, 1, 9}) || !bytes.Contains(es, []byte{0, 0, 0, 1, 5}) || bytes.Contains(es, []byte{0, 0, 0, 1, 1}) {
		t.Errorf("grabbed %d bytes: want the key PES and the one after it, and nothing before", len(es))
	}
	if strings.Count(string(es), "\x00\x00\x00\x01") != 3 {
		t.Errorf("grabbed %d NAL units, want 3", strings.Count(string(es), "\x00\x00\x00\x01"))
	}
	if a.Grabbing() {
		t.Error("still grabbing after the grab was taken")
	}
}

// TestGrabDecodes grabs a key picture from real encoder output and has ffmpeg
// turn it into a JPEG. The streams come from PACKHOUND_GRAB_TS, a list of
// files; without it, or without ffmpeg, there is nothing to test against.
func TestGrabDecodes(t *testing.T) {
	files := os.Getenv("PACKHOUND_GRAB_TS")
	if files == "" {
		t.Skip("PACKHOUND_GRAB_TS not set")
	}
	for _, f := range bytes.Fields([]byte(files)) {
		b, err := os.ReadFile(string(f))
		if err != nil {
			t.Fatal(err)
		}
		a := NewAnalyzer()
		started := false
		var es []byte
		var codec string
		for i := 0; i+7*PacketSize <= len(b); i += 7 * PacketSize {
			a.Feed(b[i : i+7*PacketSize])
			if !started {
				started = a.StartGrab()
			} else if e, c, ok := a.Grabbed(); ok {
				es, codec = e, c
				break
			}
		}
		if es == nil {
			t.Fatalf("%s: no key picture", f)
		}
		t0 := time.Now()
		cmd := exec.Command("ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin", "-threads", "1",
			"-skip_frame", "nointra", "-flags2", "showall", "-f", codec, "-i", "pipe:0", "-frames:v", "1", "-vf", "scale=320:-2", "-q:v", "5", "-f", "image2pipe", "-c:v", "mjpeg", "pipe:1")
		cmd.Stdin = bytes.NewReader(es)
		out, err := cmd.Output()
		if err != nil || len(out) < 2 || out[0] != 0xff || out[1] != 0xd8 {
			t.Fatalf("%s: ffmpeg: %v, %d bytes", f, err, len(out))
		}
		os.WriteFile(string(f)+".jpg", out, 0o644)
		t.Logf("%s: %s, %d KB grabbed, %d KB JPEG in %v", f, codec, len(es)>>10, len(out)>>10, time.Since(t0))
	}
}
