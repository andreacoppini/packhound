package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/andreacoppini/packhound/internal/monitor"
)

// Live previews: a channel transcoded small enough to watch in a browser,
// on a laptop or a phone, over a thin link. ffmpeg reads the channel's
// transport stream from a tap on the monitor (no extra joins, so it works
// for mirrored traffic too), deinterlaces, scales and encodes it with x264
// and AAC, and writes HLS: a playlist of two-second segments, which Safari
// plays as it is and other browsers play with hls.js.
//
// Encoding costs CPU on the machine running Packhound, so previews run only
// while someone watches, everyone watching a channel shares one, and only a
// few run at once.

// A quality is what a preview is encoded at.
type quality struct {
	height       int    // 0: audio only
	video, peak  string // x264 bit rate and its ceiling
	audioBitrate string
}

var qualities = map[string]quality{
	"low":     {360, "600k", "700k", "64k"},
	"verylow": {240, "280k", "330k", "48k"},
	"audio":   {0, "", "", "64k"},
}

const (
	previewIdle  = 30 * time.Second // stop this long after the last request
	previewStart = 15 * time.Second // wait this long for the first segments
)

type previews struct {
	mon    *monitor.Monitor
	ffmpeg string
	base   string // where previews write their segments
	max    int    // previews encoding at once

	mu   sync.Mutex
	live map[string]*preview // by channel key and quality
	loop sync.Once
}

type preview struct {
	key, quality, dir string
	cmd               *exec.Cmd
	tap               *monitor.Tap
	started           time.Time
	watched           time.Time
	stderr            *tailBuffer
	done              chan struct{} // closed when ffmpeg exits
}

func newPreviews(mon *monitor.Monitor, ffmpeg, base string, max int) *previews {
	if base == "" {
		base = filepath.Join(os.TempDir(), "packhound-previews")
	}
	os.RemoveAll(base) // whatever an earlier run left behind
	return &previews{mon: mon, ffmpeg: ffmpeg, base: base, max: max, live: map[string]*preview{}}
}

var errBusy = errors.New("busy")

func (ps *previews) limit() int {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.max
}

// setLimit changes how many previews may run at once. Those running carry
// on; the limit applies to the next to start.
func (ps *previews) setLimit(n int) {
	ps.mu.Lock()
	ps.max = n
	ps.mu.Unlock()
}

// get returns the running preview of a channel at a quality, starting it if
// need be, and notes that it is being watched.
func (ps *previews) get(c monitor.Channel, q string) (*preview, error) {
	ps.loop.Do(func() { go ps.reap() })
	id := c.Key + "|" + q
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if p := ps.live[id]; p != nil {
		select {
		case <-p.done: // it died: start afresh
			ps.stopLocked(id, p)
		default:
			p.watched = time.Now()
			return p, nil
		}
	}
	if len(ps.live) >= ps.max {
		return nil, errBusy
	}
	p, err := ps.start(c, q)
	if err != nil {
		return nil, err
	}
	ps.live[id] = p
	return p, nil
}

func (ps *previews) start(c monitor.Channel, q string) (*preview, error) {
	ql := qualities[q]
	if ps.ffmpeg == "" {
		return nil, errors.New("there is no ffmpeg to encode with")
	}
	if c.Scrambled {
		return nil, errors.New("the channel is scrambled")
	}
	if ql.height > 0 && c.VideoPID == 0 {
		return nil, errors.New("the channel has no video to play; try audio only")
	}
	if ql.height == 0 && c.AudioPID == 0 {
		return nil, errors.New("the channel has no audio arriving in the clear")
	}
	dir, err := os.MkdirTemp(ensureDir(ps.base), "p")
	if err != nil {
		return nil, err
	}
	args := []string{"-hide_banner", "-loglevel", "error", "-nostdin",
		"-fflags", "+genpts+discardcorrupt", "-analyzeduration", "3M", "-probesize", "3M",
		"-f", "mpegts", "-i", "pipe:0"}
	// Streams are picked by PID: the video, and the first audio track
	// arriving in the clear (a scrambled one would decode as noise).
	if ql.height > 0 {
		args = append(args, "-map", fmt.Sprintf("0:i:%d", c.VideoPID),
			"-vf", fmt.Sprintf("yadif=0:-1:1,scale=-2:%d,fps=25", ql.height),
			"-c:v", "libx264", "-preset", "veryfast", "-tune", "zerolatency", "-profile:v", "main", "-pix_fmt", "yuv420p",
			"-b:v", ql.video, "-maxrate", ql.peak, "-bufsize", ql.peak,
			"-g", "50", "-keyint_min", "50", "-sc_threshold", "0", "-threads", "1")
	}
	if c.AudioPID != 0 {
		args = append(args, "-map", fmt.Sprintf("0:i:%d", c.AudioPID),
			"-c:a", "aac", "-b:a", ql.audioBitrate, "-ac", "2", "-ar", "48000")
	}
	args = append(args, "-f", "hls", "-hls_time", "2", "-hls_list_size", "6",
		"-hls_segment_type", "fmp4", "-hls_flags", "delete_segments+independent_segments+omit_endlist",
		filepath.Join(dir, "index.m3u8"))

	tap, err := ps.mon.Tap(c.Key)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	cmd := exec.Command(ps.ffmpeg, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		tap.Close()
		os.RemoveAll(dir)
		return nil, err
	}
	tail := &tailBuffer{}
	cmd.Stderr = tail
	if err := cmd.Start(); err != nil {
		tap.Close()
		os.RemoveAll(dir)
		return nil, err
	}
	lowerPriority(cmd.Process.Pid)
	p := &preview{key: c.Key, quality: q, dir: dir, cmd: cmd, tap: tap, started: time.Now(), watched: time.Now(),
		stderr: tail, done: make(chan struct{})}
	// The tap feeds ffmpeg until it is closed or ffmpeg stops reading.
	go func() {
		w := bufio.NewWriterSize(stdin, 64<<10)
		for b := range tap.C {
			if _, err := w.Write(b); err != nil {
				break
			}
			if len(tap.C) == 0 {
				if w.Flush() != nil {
					break
				}
			}
		}
		stdin.Close()
	}()
	go func() {
		cmd.Wait()
		tap.Close() // ffmpeg died: stop feeding it
		close(p.done)
	}()
	ps.mon.Logf("Preview of %s started (%s)", c.Group, q)
	return p, nil
}

// reap stops previews nobody has asked for lately.
func (ps *previews) reap() {
	for range time.Tick(5 * time.Second) {
		ps.reapOnce()
	}
}

func (ps *previews) reapOnce() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for id, p := range ps.live {
		if time.Since(p.watched) > previewIdle {
			ps.stopLocked(id, p)
			ps.mon.Logf("Preview of %s stopped: nobody watching", p.key)
		}
	}
}

func (ps *previews) stopLocked(id string, p *preview) {
	delete(ps.live, id)
	p.tap.Close()
	go func() {
		select {
		case <-p.done:
		case <-time.After(3 * time.Second):
			p.cmd.Process.Kill()
			<-p.done
		}
		os.RemoveAll(p.dir)
	}()
}

func ensureDir(d string) string {
	os.MkdirAll(d, 0o700)
	return d
}

// segmentName is what ffmpeg names segments and the init section.
var segmentName = regexp.MustCompile(`^[A-Za-z0-9_]+\.(m4s|mp4)$`)

// serve answers prefix/<group:port>/<quality>/index.m3u8 and the segments
// it lists, and prefix itself with what is running. query is appended to
// the URLs in playlists, to carry a token.
func (ps *previews) serve(w http.ResponseWriter, r *http.Request, prefix, query string) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if rest == "" {
		ps.mu.Lock()
		type running struct {
			Channel string    `json:"channel"`
			Quality string    `json:"quality"`
			Started time.Time `json:"started"`
			Dropped uint64    `json:"dropped"`
		}
		list := []running{}
		for _, p := range ps.live {
			list = append(list, running{p.key, p.quality, p.started, p.tap.Dropped()})
		}
		ps.mu.Unlock()
		sort.Slice(list, func(i, j int) bool { return list[i].Started.Before(list[j].Started) })
		writeJSON(w, map[string]any{"max": ps.limit(), "running": list, "available": ps.ffmpeg != ""})
		return
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 {
		http.NotFound(w, r)
		return
	}
	id, err := url.PathUnescape(parts[0])
	q, file := parts[1], parts[2]
	if _, ok := qualities[q]; !ok || err != nil {
		http.NotFound(w, r)
		return
	}
	var ch *monitor.Channel
	for _, c := range ps.mon.Channels() {
		if c.Group == id {
			ch = &c
			break
		}
	}
	if ch == nil {
		previewError(w, http.StatusNotFound, "no such channel")
		return
	}
	if file == "index.m3u8" {
		p, err := ps.get(*ch, q)
		if err == errBusy {
			previewError(w, http.StatusServiceUnavailable,
				fmt.Sprintf("%d previews are already running, the most this machine allows at once; try again when one stops", ps.limit()))
			return
		}
		if err != nil {
			previewError(w, http.StatusConflict, err.Error())
			return
		}
		ps.playlist(w, r, p, query)
		return
	}
	if !segmentName.MatchString(file) {
		http.NotFound(w, r)
		return
	}
	ps.mu.Lock()
	p := ps.live[ch.Key+"|"+q]
	if p != nil {
		p.watched = time.Now()
	}
	ps.mu.Unlock()
	if p == nil {
		http.NotFound(w, r)
		return
	}
	ctype := "video/iso.segment"
	if strings.HasSuffix(file, ".mp4") {
		ctype = "video/mp4"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFile(w, r, filepath.Join(p.dir, file))
}

// playlist serves a preview's playlist, once its first segments exist, with
// query added to the URLs in it.
func (ps *previews) playlist(w http.ResponseWriter, r *http.Request, p *preview, query string) {
	path := filepath.Join(p.dir, "index.m3u8")
	deadline := time.Now().Add(previewStart)
	var b []byte
	for {
		var err error
		if b, err = os.ReadFile(path); err == nil && strings.Contains(string(b), "#EXTINF") {
			break
		}
		select {
		case <-p.done:
			msg := "the encoder stopped"
			if t := strings.TrimSpace(p.stderr.String()); t != "" {
				msg += ": " + t
			}
			previewError(w, http.StatusBadGateway, msg)
			return
		case <-r.Context().Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			previewError(w, http.StatusGatewayTimeout, "no picture yet: the channel may have stopped")
			return
		}
	}
	out := string(b)
	if query != "" {
		var sb strings.Builder
		for _, line := range strings.Split(out, "\n") {
			switch {
			case strings.HasPrefix(line, "#EXT-X-MAP:URI=\""):
				line = strings.Replace(line, ".mp4\"", ".mp4?"+query+"\"", 1)
			case line != "" && !strings.HasPrefix(line, "#"):
				line += "?" + query
			}
			sb.WriteString(line + "\n")
		}
		out = sb.String()
	}
	w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
	w.Header().Set("Cache-Control", "no-cache")
	io.WriteString(w, out)
}

func previewError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, "{\"error\":%q}\n", msg)
}

// tailBuffer keeps the end of what a process writes to stderr.
type tailBuffer struct {
	mu sync.Mutex
	b  []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b = append(t.b, p...)
	if len(t.b) > 2048 {
		t.b = t.b[len(t.b)-2048:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.b)
}
