package main

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/andreacoppini/packhound/internal/capture"
	"github.com/andreacoppini/packhound/internal/demo"
	"github.com/andreacoppini/packhound/internal/groups"
	"github.com/andreacoppini/packhound/internal/monitor"
	"github.com/andreacoppini/packhound/internal/pkt"
)

// Listening modes.
const (
	modeCapture = "capture"
	modeJoin    = "join"
	modeDemo    = "demo"
)

// startRequest is what the console or the command line asks for.
type startRequest struct {
	Iface  string `json:"iface"`
	Mode   string `json:"mode"`
	Groups string `json:"groups"`
	Join   bool   `json:"join"` // with capture: also join the listed groups
}

// engine runs one listening session at a time, feeding the monitor.
type engine struct {
	mon *monitor.Monitor

	mu       sync.Mutex
	running  bool
	mode     string // what is actually running, after any fallback
	iface    string
	started  time.Time
	src      capture.Source
	joins    *capture.Joined
	rec      *recorder
	lastRec  *recordingStatus
	done     chan struct{}
	stopTick chan struct{}
	failed   string // why the last session ended on its own
}

func newEngine(cfg monitor.Config) *engine {
	return &engine{mon: monitor.New(cfg)}
}

type engineStatus struct {
	Running   bool             `json:"running"`
	Mode      string           `json:"mode"`
	Iface     string           `json:"iface"`
	Started   time.Time        `json:"started"`
	Joined    int              `json:"joined"`
	Failed    string           `json:"failed,omitempty"`
	Recording *recordingStatus `json:"recording,omitempty"`
}

func (e *engine) status() engineStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := engineStatus{Running: e.running, Mode: e.mode, Iface: e.iface, Started: e.started, Failed: e.failed}
	if e.joins != nil {
		s.Joined = e.joins.Count()
	}
	if e.rec != nil {
		r := e.rec.status()
		s.Recording = &r
	} else if e.lastRec != nil {
		s.Recording = e.lastRec
	}
	return s
}

// start begins listening. Live capture that cannot start falls back to
// joining, with the reason in the log, rather than failing: a monitor that
// shows the listed groups is more use than an error.
func (e *engine) start(req startRequest) error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return errors.New("already listening; stop first")
	}
	e.mu.Unlock()

	var gs []groups.Group
	if strings.TrimSpace(req.Groups) != "" {
		var err error
		if gs, err = groups.Parse(req.Groups); err != nil {
			return err
		}
	}

	var ifc capture.Interface
	if req.Mode != modeDemo {
		var err error
		if ifc, err = capture.FindInterface(req.Iface); err != nil {
			return err
		}
	}

	e.mon.Reset()
	mode := req.Mode
	var src capture.Source
	var joins *capture.Joined

	switch mode {
	case modeDemo:
		src = demoSource{demo.New()}
		e.mon.Logf("Demo traffic: nothing here is real")
	case modeCapture:
		live, err := capture.OpenLive(ifc)
		if err != nil {
			if len(gs) == 0 {
				return fmt.Errorf("%v (or list some groups and join them instead)", err)
			}
			e.mon.Logf("Live capture unavailable: %v", err)
			e.mon.Logf("Falling back to joining the listed groups")
			mode = modeJoin
		} else {
			src = live
			e.mon.Logf("Capturing every multicast frame on %s", ifc.Name)
		}
	}
	if mode == modeJoin || (mode == modeCapture && req.Join && len(gs) > 0) {
		if len(gs) == 0 {
			return errors.New("list the groups to join, one per line, as 239.1.1.1:5000")
		}
		open := capture.OpenJoin
		if mode == modeCapture {
			// Capture reads the traffic; these sockets only hold the joins.
			open = capture.OpenHold
		}
		j, err := open(ifc, gs)
		if err != nil {
			if src != nil {
				src.Close()
			}
			return err
		}
		for _, f := range j.Failed {
			e.mon.Logf("Could not join %s", f)
		}
		e.mon.Logf("Joined %d groups on %s", j.Count(), ifc.Name)
		joins = j
		if mode == modeJoin {
			src = j
		}
	}
	if src == nil {
		return fmt.Errorf("unknown mode %q", req.Mode)
	}

	e.mu.Lock()
	e.running, e.mode, e.started, e.failed = true, mode, time.Now(), ""
	e.iface = ifc.Name
	if mode == modeDemo {
		e.iface = "demo"
	}
	e.src, e.joins = src, joins
	e.done, e.stopTick = make(chan struct{}), make(chan struct{})
	e.mu.Unlock()

	go e.tick(e.stopTick, src)
	go e.read(src, e.done)
	return nil
}

// tick drives the monitor's once-a-second work, a quarter of a second after
// each second turns: joined groups are read in batches a tenth of a second
// apart, so by then the second's last datagrams are in.
func (e *engine) tick(stop chan struct{}, src capture.Source) {
	d, _ := src.(capture.Dropper)
	var seen uint64
	for {
		now := time.Now()
		next := now.Truncate(time.Second).Add(time.Second + 250*time.Millisecond)
		select {
		case <-stop:
			return
		case <-time.After(next.Sub(now)):
			t := time.Now()
			var n uint64
			if d != nil {
				if v := d.Dropped(); v > seen {
					n, seen = v-seen, v
				}
			}
			e.mon.NoteLocalDrops(t, n)
			e.mon.Tick(t)
		}
	}
}

// batchSource is a source that can hand over many datagrams at once.
type batchSource interface {
	NextBatch() ([]pkt.Packet, error)
}

func (e *engine) read(src capture.Source, done chan struct{}) {
	defer close(done)
	if bs, ok := src.(batchSource); ok {
		e.readBatches(bs, done)
		return
	}
	var p pkt.Packet
	for {
		f, err := src.Next()
		if err != nil {
			if !errors.Is(err, capture.ErrClosed) {
				e.mon.Logf("Capture stopped: %v", err)
				e.mu.Lock()
				e.failed = err.Error()
				e.mu.Unlock()
				go e.stop()
			}
			return
		}
		var raw []byte
		if f.Pkt != nil {
			p = *f.Pkt
		} else {
			if !pkt.Decode(f.Link, f.Data, f.Time, &p) {
				continue
			}
			if f.Link == pkt.LinkEthernet {
				raw = f.Data
			}
		}
		e.mon.Ingest(&p)
		e.mu.Lock()
		rec := e.rec
		e.mu.Unlock()
		if rec != nil {
			rec.write(&p, raw)
		}
	}
}

func (e *engine) readBatches(src batchSource, done chan struct{}) {
	for {
		ps, err := src.NextBatch()
		if err != nil {
			if !errors.Is(err, capture.ErrClosed) {
				e.mon.Logf("Capture stopped: %v", err)
				e.mu.Lock()
				e.failed = err.Error()
				e.mu.Unlock()
				go e.stop()
			}
			return
		}
		e.mon.IngestBatch(ps)
		e.mu.Lock()
		rec := e.rec
		e.mu.Unlock()
		if rec != nil {
			for i := range ps {
				rec.write(&ps[i], nil)
			}
		}
	}
}

// stop ends the session. Streams stay on screen until the next start.
func (e *engine) stop() {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return
	}
	src, joins, done, stopTick := e.src, e.joins, e.done, e.stopTick
	e.running = false
	e.mu.Unlock()

	src.Close()
	if joins != nil && joins != src {
		joins.Close()
	}
	close(stopTick)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	e.stopRecording()
	e.mu.Lock()
	e.src, e.joins = nil, nil
	e.mu.Unlock()
	e.mon.Logf("Stopped listening")
}

func (e *engine) startRecording() (recordingStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.running {
		return recordingStatus{}, errors.New("start listening first")
	}
	if e.rec != nil {
		return e.rec.status(), nil
	}
	r, err := newRecorder(recordingDir())
	if err != nil {
		return recordingStatus{}, err
	}
	e.rec = r
	e.mon.Logf("Recording to %s", r.path)
	return r.status(), nil
}

func (e *engine) stopRecording() {
	e.mu.Lock()
	r := e.rec
	e.rec = nil
	e.mu.Unlock()
	if r == nil {
		return
	}
	if err := r.close(); err != nil {
		e.mon.Logf("Recording failed: %v", err)
	}
	st := r.status()
	e.mu.Lock()
	e.lastRec = &st
	e.mu.Unlock()
	msg := "Recording saved: " + st.String()
	if st.Full {
		msg += " (stopped at the 2 GB limit)"
	}
	e.mon.Logf("%s", msg)
}

// demoSource adapts the demo generator to capture.Source.
type demoSource struct{ d *demo.Source }

func (s demoSource) Next() (capture.Frame, error) {
	b, t, err := s.d.Next()
	if err != nil {
		return capture.Frame{}, capture.ErrClosed
	}
	return capture.Frame{Data: b, Link: pkt.LinkEthernet, Time: t}, nil
}

func (s demoSource) Close() error { return s.d.Close() }
