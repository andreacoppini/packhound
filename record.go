package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/andreacoppini/packhound/internal/pkt"
)

// recorder writes the multicast traffic being monitored to a pcap file that
// Wireshark opens. Frames from live Ethernet capture are written as they
// arrived; anything else (joined sockets, the demo, loopback) is written as a
// rebuilt Ethernet frame, since the socket never saw the original headers.
type recorder struct {
	mu      sync.Mutex
	path    string
	f       *os.File
	w       *bufio.Writer
	size    int64
	frames  uint64
	started time.Time
	full    bool
}

// recordingLimit stops a recording before it fills a disk: an hour of a
// busy IPTV feed is tens of gigabytes.
const recordingLimit = 2 << 30

// recordingDir is where recordings go: Downloads if there is one, else the
// working directory.
func recordingDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		d := filepath.Join(home, "Downloads")
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			return d
		}
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

func newRecorder(dir string) (*recorder, error) {
	name := "packhound-" + time.Now().Format("20060102-150405") + ".pcap"
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, err
	}
	r := &recorder{path: path, f: f, w: bufio.NewWriterSize(f, 1<<20), started: time.Now()}
	// Nanosecond-resolution pcap, Ethernet, 64 KiB snapshot length.
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h[0:], 0xa1b23c4d)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], 65535)
	binary.LittleEndian.PutUint32(h[20:], pkt.LinkEthernet)
	if _, err := r.w.Write(h); err != nil {
		f.Close()
		return nil, err
	}
	r.size = 24
	return r, nil
}

// write records one packet. frame is the raw frame when it is Ethernet, else
// nil and the frame is rebuilt from p.
func (r *recorder) write(p *pkt.Packet, frame []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil || r.full {
		return
	}
	if frame == nil {
		if p.Frag == pkt.Later {
			return
		}
		frame = pkt.Rebuild(p)
	}
	if r.size+16+int64(len(frame)) > recordingLimit {
		r.full = true
		return
	}
	var h [16]byte
	ns := p.Time.UnixNano()
	binary.LittleEndian.PutUint32(h[0:], uint32(ns/1e9))
	binary.LittleEndian.PutUint32(h[4:], uint32(ns%1e9))
	binary.LittleEndian.PutUint32(h[8:], uint32(len(frame)))
	binary.LittleEndian.PutUint32(h[12:], uint32(len(frame)))
	r.w.Write(h[:])
	r.w.Write(frame)
	r.size += 16 + int64(len(frame))
	r.frames++
}

func (r *recorder) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.w.Flush()
	if cerr := r.f.Close(); err == nil {
		err = cerr
	}
	r.f = nil
	return err
}

func (r *recorder) status() recordingStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return recordingStatus{
		Active: r.f != nil, Path: r.path, Name: filepath.Base(r.path),
		Frames: r.frames, Bytes: r.size, Full: r.full,
		Seconds: int(time.Since(r.started).Seconds()),
	}
}

type recordingStatus struct {
	Active  bool   `json:"active"`
	Path    string `json:"path"`
	Name    string `json:"name"`
	Frames  uint64 `json:"frames"`
	Bytes   int64  `json:"bytes"`
	Seconds int    `json:"seconds"`
	Full    bool   `json:"full"`
}

func (s recordingStatus) String() string {
	return fmt.Sprintf("%s: %d packets, %.1f MB", s.Path, s.Frames, float64(s.Bytes)/(1<<20))
}
