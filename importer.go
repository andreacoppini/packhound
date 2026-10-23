package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreacoppini/packhound/internal/monitor"
	"github.com/andreacoppini/packhound/internal/pcapfile"
	"github.com/andreacoppini/packhound/internal/pkt"
)

// A capture file, read after the fact into a monitor of its own: the live
// monitor, and the SNMP agent and REST API that report it, carry on while
// someone looks at a file.
//
// The file is replayed on its own clock, as fast as it reads: packets go in
// in order, and the monitor ticks at each whole second of capture time, so
// rates, MDI and alerts come out as they would have live, stamped with the
// capture's times. Ticking stops at the last packet, so the result is the
// state of things when the capture ended.
type fileView struct {
	Name     string    `json:"name"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	Frames   uint64    `json:"frames"`   // in the file
	Packets  uint64    `json:"packets"`  // multicast datagrams analysed
	Mirrored uint64    `json:"mirrored"` // of which unwrapped from ERSPAN or TZSP
	Read     int64     `json:"read"`     // bytes of the file read
	Size     int64     `json:"size"`     // the file's size, when known
	Done     bool      `json:"done"`
	Error    string    `json:"error,omitempty"`

	mon    *monitor.Monitor
	mosaic *mosaic
}

// maxImport bounds an uploaded capture file.
const maxImport = 4 << 30

// readCapture reads a capture file into v's monitor, updating v as it goes.
// mu guards v's exported fields against readers of the progress.
func readCapture(r io.Reader, v *fileView, mu *sync.Mutex) error {
	var n atomic.Int64
	rd, err := pcapfile.NewReader(countingReader{r, &n})
	if err != nil {
		return err
	}
	set := func(f func()) {
		mu.Lock()
		f()
		v.Read = n.Load()
		mu.Unlock()
	}
	var p pkt.Packet
	var next time.Time // the next whole second of capture time to tick at
	var frames, packets, mirrored uint64
	for {
		data, link, ts, err := rd.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		frames++
		if next.IsZero() {
			next = ts.Truncate(time.Second).Add(time.Second)
			set(func() { v.First = ts })
			v.mon.LogAt(ts, "Reading capture file %s", v.Name)
		}
		if !ts.Before(next) {
			// A gap of more than an hour (or a clock that jumped) is
			// skipped in one step rather than ticked through.
			if ts.Sub(next) > time.Hour {
				next = ts.Truncate(time.Second)
			}
			for !ts.Before(next) {
				v.mon.Tick(next)
				v.mosaic.grabStatic(next, false)
				next = next.Add(time.Second)
			}
			set(func() { v.Frames, v.Packets, v.Mirrored, v.Last = frames, packets, mirrored, ts })
		}
		ok := pkt.Decode(link, data, ts, &p)
		if !ok {
			if inner, unwrapped := pkt.Unwrap(link, data); unwrapped {
				ok = pkt.Decode(pkt.LinkEthernet, inner, ts, &p)
				if ok {
					mirrored++
				}
			}
		}
		if ok {
			packets++
			v.mon.Ingest(&p)
			if p.Time.After(v.Last) {
				set(func() { v.Last = p.Time })
			}
		}
	}
	if !next.IsZero() {
		v.mon.Tick(next)
		v.mosaic.grabStatic(next, true)
	}
	set(func() { v.Frames, v.Packets, v.Mirrored = frames, packets, mirrored })
	if frames == 0 {
		return errors.New("the file holds no packets")
	}
	v.mon.LogAt(v.Last, "Read %d frames, of which %d multicast packets", frames, packets)
	if mirrored > 0 {
		v.mon.LogAt(v.Last, "%d packets were mirrored traffic, unwrapped from ERSPAN or TZSP", mirrored)
	}
	if packets == 0 {
		v.mon.LogAt(v.Last, "No multicast traffic in the file")
	}
	return nil
}

type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c countingReader) Read(b []byte) (int, error) {
	k, err := c.r.Read(b)
	c.n.Add(int64(k))
	return k, err
}

// newFileView makes an empty view of a capture file, with the alert
// thresholds the live monitor uses.
func newFileView(name string, cfg monitor.Config, ffmpeg string) *fileView {
	cfg.Offline = true
	mon := monitor.New(cfg)
	mos := newMosaic(mon)
	mos.ffmpeg, mos.static = ffmpeg, true
	return &fileView{Name: name, mon: mon, mosaic: mos}
}

// ---- console ----

// handleImport takes an uploaded capture file (POST, the file as the body,
// ?name= its name), reports the one being read or shown (GET), or closes it
// (DELETE).
func (c *console) handleImport(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c.mu.Lock()
		var st any
		if c.file != nil {
			v := *c.file
			st = v
		}
		c.mu.Unlock()
		writeJSON(w, map[string]any{"file": st})
	case http.MethodDelete:
		c.mu.Lock()
		if c.file != nil && c.file.Done {
			c.file = nil
		}
		c.mu.Unlock()
		writeJSON(w, map[string]any{"file": nil})
	case http.MethodPost:
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			name = "capture"
		}
		c.mu.Lock()
		if c.file != nil && !c.file.Done {
			c.mu.Unlock()
			writeErr(w, errors.New("a capture file is still being read"))
			return
		}
		v := newFileView(name, c.eng.mon.Config(), c.mosaic.ffmpeg)
		v.Size = r.ContentLength
		c.file = v
		c.mu.Unlock()

		err := readCapture(http.MaxBytesReader(w, r.Body, maxImport), v, &c.mu)
		c.mu.Lock()
		v.Done = true
		if err != nil {
			v.Error = err.Error()
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				v.Error = fmt.Sprintf("the file is over %d GB", maxImport>>30)
			}
		}
		st := *v
		c.mu.Unlock()
		if err != nil {
			writeErr(w, errors.New(st.Error))
			return
		}
		writeJSON(w, map[string]any{"file": st})
	default:
		http.Error(w, "GET, POST or DELETE", http.StatusMethodNotAllowed)
	}
}

// viewMonitor is the monitor a request asks about: the capture file's when
// it says view=file and one is open, else the live one.
func (c *console) viewMonitor(r *http.Request) (*monitor.Monitor, *fileView) {
	if r.URL.Query().Get("view") == "file" {
		c.mu.Lock()
		v := c.file
		c.mu.Unlock()
		if v != nil {
			return v.mon, v
		}
	}
	return c.eng.mon, nil
}
