package pcapfile

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

// order is a byte order that can also append.
type order interface {
	binary.ByteOrder
	binary.AppendByteOrder
}

var t0 = time.Date(2026, 10, 23, 14, 2, 11, 123456000, time.UTC)

func frames() [][]byte {
	return [][]byte{bytes.Repeat([]byte{1}, 60), bytes.Repeat([]byte{2}, 1358), {3, 3, 3}}
}

// classic writes a classic pcap file.
func classic(bo order, nano bool) []byte {
	var b []byte
	magic := uint32(0xa1b2c3d4)
	if nano {
		magic = 0xa1b23c4d
	}
	b = bo.AppendUint32(b, magic)
	b = bo.AppendUint16(b, 2)
	b = bo.AppendUint16(b, 4)
	b = append(b, make([]byte, 8)...)
	b = bo.AppendUint32(b, 65535)
	b = bo.AppendUint32(b, 1)
	for i, f := range frames() {
		ts := t0.Add(time.Duration(i) * time.Millisecond)
		frac := ts.Nanosecond()
		if !nano {
			frac /= 1000
		}
		b = bo.AppendUint32(b, uint32(ts.Unix()))
		b = bo.AppendUint32(b, uint32(frac))
		b = bo.AppendUint32(b, uint32(len(f)))
		b = bo.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return b
}

func block(bo order, typ uint32, body []byte) []byte {
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	n := uint32(12 + len(body))
	b := bo.AppendUint32(nil, typ)
	b = bo.AppendUint32(b, n)
	b = append(b, body...)
	return bo.AppendUint32(b, n)
}

// pcapng writes a pcapng file: a section with an interface of the given
// timestamp resolution, the frames as enhanced packet blocks with an
// unknown block among them, and a simple packet block at the end.
func pcapng(bo order, tsresol byte, link uint16) []byte {
	shb := bo.AppendUint32(nil, 0x1a2b3c4d)
	shb = bo.AppendUint16(shb, 1)
	shb = bo.AppendUint16(shb, 0)
	shb = append(shb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	b := block(bo, 0x0a0d0d0a, shb)
	idb := bo.AppendUint16(nil, link)
	idb = bo.AppendUint16(idb, 0)
	idb = bo.AppendUint32(idb, 65535)
	if tsresol != 0 {
		idb = bo.AppendUint16(idb, 9)
		idb = bo.AppendUint16(idb, 1)
		idb = append(idb, tsresol, 0, 0, 0)
		idb = bo.AppendUint32(idb, 0) // end of options
	}
	b = append(b, block(bo, 1, idb)...)
	units := uint64(1e6)
	if tsresol == 9 {
		units = 1e9
	}
	for i, f := range frames() {
		ts := t0.Add(time.Duration(i) * time.Millisecond)
		v := uint64(ts.UnixNano()) / (1e9 / units)
		e := bo.AppendUint32(nil, 0)
		e = bo.AppendUint32(e, uint32(v>>32))
		e = bo.AppendUint32(e, uint32(v))
		e = bo.AppendUint32(e, uint32(len(f)))
		e = bo.AppendUint32(e, uint32(len(f)))
		b = append(b, block(bo, 6, append(e, f...))...)
		if i == 0 {
			b = append(b, block(bo, 5, []byte("interface statistics"))...)
		}
	}
	spb := bo.AppendUint32(nil, 4)
	return append(b, block(bo, 3, append(spb, 9, 9, 9, 9))...)
}

func read(t *testing.T, name string, file []byte) (got [][]byte, times []time.Time, links []int) {
	r, err := NewReader(bytes.NewReader(file))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	for {
		d, link, ts, err := r.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got = append(got, append([]byte(nil), d...))
		times = append(times, ts)
		links = append(links, link)
	}
}

func TestClassic(t *testing.T) {
	for _, c := range []struct {
		name string
		bo   order
		nano bool
	}{{"little-endian µs", binary.LittleEndian, false}, {"big-endian ns", binary.BigEndian, true}} {
		got, times, links := read(t, c.name, classic(c.bo, c.nano))
		want := frames()
		if len(got) != len(want) {
			t.Fatalf("%s: %d frames", c.name, len(got))
		}
		for i := range want {
			if !bytes.Equal(got[i], want[i]) || links[i] != 1 || !times[i].Equal(t0.Add(time.Duration(i)*time.Millisecond)) {
				t.Errorf("%s frame %d: %d bytes, link %d, %v", c.name, i, len(got[i]), links[i], times[i])
			}
		}
	}
}

func TestPcapng(t *testing.T) {
	for _, c := range []struct {
		name    string
		bo      order
		tsresol byte
		link    uint16
	}{{"little-endian ns", binary.LittleEndian, 9, 1}, {"big-endian µs SLL2", binary.BigEndian, 0, 276}} {
		file := pcapng(c.bo, c.tsresol, c.link)
		// A second section, as mergecap writes, has its own interfaces.
		file = append(file, pcapng(c.bo, c.tsresol, c.link)...)
		got, times, links := read(t, c.name, file)
		want := append(frames(), []byte{9, 9, 9, 9})
		want = append(want, want...)
		if len(got) != len(want) {
			t.Fatalf("%s: %d frames, want %d", c.name, len(got), len(want))
		}
		for i := range want {
			wantT := t0.Add(time.Duration(i%4) * time.Millisecond)
			if i%4 == 3 {
				wantT = t0.Add(2 * time.Millisecond) // simple packets take the time before
			}
			if !bytes.Equal(got[i], want[i]) || links[i] != int(c.link) || !times[i].Equal(wantT) {
				t.Errorf("%s frame %d: %d bytes, link %d, %v", c.name, i, len(got[i]), links[i], times[i])
			}
		}
	}
}

func TestNotACapture(t *testing.T) {
	if _, err := NewReader(bytes.NewReader([]byte("PK\x03\x04 a zip file"))); err != ErrFormat {
		t.Errorf("err %v", err)
	}
}

// TestCutShort keeps the frames before a truncated last record, as a
// capture stopped by pulling the plug leaves it.
func TestCutShort(t *testing.T) {
	file := classic(binary.LittleEndian, false)
	got, _, _ := read(t, "cut", file[:len(file)-2])
	if len(got) != 2 {
		t.Errorf("%d frames, want 2", len(got))
	}
}
