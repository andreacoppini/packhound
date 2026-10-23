package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/andreacoppini/packhound/internal/monitor"
)

// The mosaic shows a still of every channel, refreshed every few seconds.
// A still is one key picture: its packets are copied out of the stream as it
// passes through the analyser (no extra joins), and ffmpeg decodes it into a
// small JPEG. Decoding is the costly part, so one picture is decoded at a
// time and decoding is held to a share of one core: with many channels the
// round simply takes longer.
const (
	mosaicInterval = 10 * time.Second
	mosaicBudget   = 0.25            // share of one core spent decoding, at most
	mosaicIdle     = 5 * time.Minute // stop grabbing this long after the last look
	grabTimeout    = 15 * time.Second
	maxGrabs       = 8 // grabs collecting or waiting to be decoded
	thumbWidth     = 320
)

type mosaic struct {
	mon    *monitor.Monitor
	ffmpeg string // "" when there is no decoder

	mu     sync.Mutex
	shots  map[string]*shot // by channel key
	looked time.Time        // when someone last asked for the mosaic
	jobs   chan decodeJob
	loop   sync.Once
}

type shot struct {
	jpeg     []byte
	etag     string
	at       time.Time // when the picture was taken
	tried    time.Time // when a grab last started
	grabbing time.Time // zero unless a grab is collecting
	queued   bool      // grabbed, waiting for the decoder
	problem  string    // why there is no recent picture
}

type decodeJob struct {
	key, codec string
	es         []byte
	at         time.Time
}

func newMosaic(mon *monitor.Monitor) *mosaic {
	return &mosaic{mon: mon, ffmpeg: findFFmpeg(), shots: map[string]*shot{}, jobs: make(chan decodeJob, maxGrabs)}
}

// findFFmpeg looks for a decoder: one named in PACKHOUND_FFMPEG, the one the
// appliance ships, one beside this program, then any on the PATH.
func findFFmpeg() string {
	exe := "ffmpeg"
	if runtime.GOOS == "windows" {
		exe = "ffmpeg.exe"
	}
	cands := []string{os.Getenv("PACKHOUND_FFMPEG"), "/usr/lib/packhound/ffmpeg"}
	if self, err := os.Executable(); err == nil {
		cands = append(cands, filepath.Join(filepath.Dir(self), exe))
	}
	for _, c := range cands {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	if p, err := exec.LookPath(exe); err == nil {
		return p
	}
	return ""
}

// touch notes that someone is looking, and starts the grabber.
func (m *mosaic) touch() {
	m.mu.Lock()
	m.looked = time.Now()
	m.mu.Unlock()
	m.loop.Do(func() {
		go m.run()
		if m.ffmpeg != "" {
			go m.decoder()
		}
	})
}

func (m *mosaic) run() {
	for range time.Tick(500 * time.Millisecond) {
		m.step(time.Now())
	}
}

// step starts grabs that are due, collects finished ones, and gives up on
// those that found no key picture in time.
func (m *mosaic) step(now time.Time) {
	m.mu.Lock()
	active := m.ffmpeg != "" && now.Sub(m.looked) < mosaicIdle
	idle := !active
	for _, sh := range m.shots {
		if !sh.grabbing.IsZero() {
			idle = false
		}
	}
	m.mu.Unlock()
	if idle {
		return
	}
	chans := m.mon.Channels()
	m.mu.Lock()
	seen := map[string]bool{}
	busy := 0
	var grabbing []string
	for _, c := range chans {
		seen[c.Key] = true
		sh := m.shots[c.Key]
		if sh == nil {
			sh = &shot{}
			m.shots[c.Key] = sh
		}
		if !sh.grabbing.IsZero() {
			grabbing = append(grabbing, c.Key)
		}
		if !sh.grabbing.IsZero() || sh.queued {
			busy++
		}
	}
	for k, sh := range m.shots {
		if !seen[k] {
			if !sh.grabbing.IsZero() {
				m.mon.StopGrab(k)
			}
			delete(m.shots, k)
		}
	}
	m.mu.Unlock()

	// Finished grabs go to the decoder; stale ones are dropped.
	for _, k := range grabbing {
		es, codec, ok := m.mon.Grabbed(k)
		m.mu.Lock()
		sh := m.shots[k]
		switch {
		case ok:
			sh.grabbing, sh.queued = time.Time{}, true
			m.mu.Unlock()
			m.jobs <- decodeJob{key: k, codec: codec, es: es, at: now}
			continue
		case !active || now.Sub(sh.grabbing) > grabTimeout:
			m.mon.StopGrab(k)
			if active {
				sh.problem = fmt.Sprintf("no key picture in %s", grabTimeout)
			}
			sh.grabbing = time.Time{}
			busy--
		}
		m.mu.Unlock()
	}
	if !active {
		return
	}

	// Start the grabs that are most overdue.
	type due struct {
		key  string
		last time.Time
	}
	var todo []due
	m.mu.Lock()
	for _, c := range chans {
		sh := m.shots[c.Key]
		switch {
		case c.Codec == "":
			sh.problem = "no video this decoder reads"
			if c.Video == "" {
				sh.problem = "no video"
			}
			if c.Scrambled {
				sh.problem = "scrambled"
			}
			continue
		case c.Scrambled:
			sh.problem = "scrambled"
			continue
		case c.Status == monitor.Lost:
			continue
		}
		if sh.grabbing.IsZero() && !sh.queued && now.Sub(sh.tried) >= mosaicInterval {
			todo = append(todo, due{c.Key, sh.tried})
		}
	}
	m.mu.Unlock()
	sort.Slice(todo, func(i, j int) bool { return todo[i].last.Before(todo[j].last) })
	for _, d := range todo {
		if busy >= maxGrabs {
			break
		}
		if !m.mon.StartGrab(d.key) {
			continue
		}
		m.mu.Lock()
		if sh := m.shots[d.key]; sh != nil {
			sh.grabbing, sh.tried = now, now
			busy++
		}
		m.mu.Unlock()
	}
}

// decoder turns grabbed pictures into JPEGs, one at a time, resting after
// each so that decoding stays within its share of a core.
func (m *mosaic) decoder() {
	for j := range m.jobs {
		img, cpu, err := m.decode(j)
		m.mu.Lock()
		if sh := m.shots[j.key]; sh != nil {
			sh.queued = false
			if err != nil {
				sh.problem = "could not decode the picture"
			} else {
				sum := sha1.Sum(img)
				sh.jpeg, sh.etag, sh.at, sh.problem = img, `"`+hex.EncodeToString(sum[:8])+`"`, j.at, ""
			}
		}
		m.mu.Unlock()
		time.Sleep(time.Duration(float64(cpu) * (1/mosaicBudget - 1)))
	}
}

func (m *mosaic) decode(j decodeJob) ([]byte, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Scale to the display aspect, so anamorphic SD comes out 16:9.
	cmd := exec.CommandContext(ctx, m.ffmpeg, "-hide_banner", "-loglevel", "error", "-nostdin", "-threads", "1",
		"-f", j.codec, "-i", "pipe:0", "-frames:v", "1",
		"-vf", fmt.Sprintf("scale=%d:trunc(ow/dar/2)*2", thumbWidth),
		"-q:v", "5", "-f", "image2pipe", "-c:v", "mjpeg", "pipe:1")
	cmd.Stdin = bytes.NewReader(j.es)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	var cpu time.Duration
	if cmd.ProcessState != nil {
		cpu = cmd.ProcessState.UserTime() + cmd.ProcessState.SystemTime()
	}
	b := out.Bytes()
	if err == nil && (len(b) < 4 || b[0] != 0xff || b[1] != 0xd8) {
		err = fmt.Errorf("no picture")
	}
	return b, cpu, err
}

// mosaicChannel is a channel with its latest still.
type mosaicChannel struct {
	monitor.Channel
	ID string `json:"id"` // the channel in image URLs: its group and port
	// Image is the still's URL, empty until one is taken.
	Image   string    `json:"image,omitempty"`
	ShotAt  time.Time `json:"shotAt,omitzero"`
	Problem string    `json:"problem,omitempty"`
}

// serveMosaic answers prefix (the list, as JSON) and prefix/<id>.jpg (one
// channel's still). query is appended to image URLs, to carry a token.
func (m *mosaic) serve(w http.ResponseWriter, r *http.Request, prefix, query string) {
	m.touch()
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	if rest == "" || rest == "/" {
		chans := m.mon.Channels()
		out := make([]mosaicChannel, 0, len(chans))
		m.mu.Lock()
		for _, c := range chans {
			mc := mosaicChannel{Channel: c, ID: c.Group}
			if sh := m.shots[c.Key]; sh != nil {
				mc.Problem = sh.problem
				if sh.jpeg != nil {
					mc.ShotAt = sh.at
					mc.Image = prefix + "/" + url.PathEscape(c.Group) + ".jpg?v=" + strings.Trim(sh.etag, `"`) + query
				}
			}
			out = append(out, mc)
		}
		m.mu.Unlock()
		info := map[string]any{"time": time.Now().UTC(), "interval": mosaicInterval.Seconds(), "decoder": m.ffmpeg != "", "channels": out}
		if m.ffmpeg == "" {
			info["note"] = "ffmpeg was not found, so there are no pictures: install it, or put it beside packhound"
		}
		writeJSON(w, info)
		return
	}
	id, err := url.PathUnescape(strings.TrimSuffix(strings.TrimPrefix(rest, "/"), ".jpg"))
	if err != nil || !strings.HasSuffix(rest, ".jpg") {
		http.NotFound(w, r)
		return
	}
	var key string
	for _, c := range m.mon.Channels() {
		if c.Group == id {
			key = c.Key
		}
	}
	m.mu.Lock()
	sh := m.shots[key]
	var img []byte
	var etag string
	var at time.Time
	if sh != nil {
		img, etag, at = sh.jpeg, sh.etag, sh.at
	}
	m.mu.Unlock()
	if img == nil {
		http.Error(w, "no picture yet", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Last-Modified", at.UTC().Format(http.TimeFormat))
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(img)
}
