// Package pcapfile reads capture files: classic pcap, as tcpdump writes, and
// pcapng, as Wireshark writes by default. Files are read as a stream, so
// their size does not matter.
package pcapfile

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

// maxFrame bounds a single frame or block: anything bigger is a damaged
// file, not traffic.
const maxFrame = 16 << 20

// Reader returns the frames of a capture file in order.
type Reader struct {
	r   *bufio.Reader
	buf []byte

	ng bool
	bo binary.ByteOrder

	// Classic pcap.
	link int
	nano bool

	// pcapng: the interfaces of the current section.
	ifaces []iface
	last   time.Time // for simple packet blocks, which carry no time
}

type iface struct {
	link  int
	units float64 // timestamp units per second
}

// ErrFormat is returned for files that are not pcap or pcapng.
var ErrFormat = errors.New("not a pcap or pcapng file")

// NewReader reads the file header.
func NewReader(r io.Reader) (*Reader, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	head, err := br.Peek(4)
	if err != nil {
		return nil, ErrFormat
	}
	pr := &Reader{r: br}
	switch {
	case binary.LittleEndian.Uint32(head) == 0x0a0d0d0a:
		pr.ng = true
		return pr, nil
	case binary.LittleEndian.Uint32(head) == 0xa1b2c3d4:
		pr.bo = binary.LittleEndian
	case binary.BigEndian.Uint32(head) == 0xa1b2c3d4:
		pr.bo = binary.BigEndian
	case binary.LittleEndian.Uint32(head) == 0xa1b23c4d:
		pr.bo, pr.nano = binary.LittleEndian, true
	case binary.BigEndian.Uint32(head) == 0xa1b23c4d:
		pr.bo, pr.nano = binary.BigEndian, true
	default:
		return nil, ErrFormat
	}
	h := make([]byte, 24)
	if _, err := io.ReadFull(br, h); err != nil {
		return nil, ErrFormat
	}
	// The link type is the low 16 bits; the high bits can carry FCS flags.
	pr.link = int(pr.bo.Uint32(h[20:]) & 0xffff)
	return pr, nil
}

// Next returns the next frame, its link type (numbered as pcap numbers
// them) and its time. data is only valid until the next call. At the end of
// the file it returns io.EOF.
func (r *Reader) Next() (data []byte, link int, ts time.Time, err error) {
	if r.ng {
		return r.nextNG()
	}
	var h [16]byte
	if _, err := io.ReadFull(r.r, h[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			err = io.EOF // a file cut off mid-record: keep what was read
		}
		return nil, 0, time.Time{}, err
	}
	caplen := r.bo.Uint32(h[8:])
	if caplen > maxFrame {
		return nil, 0, time.Time{}, fmt.Errorf("damaged file: a %d-byte frame", caplen)
	}
	data, err = r.read(int(caplen))
	if err != nil {
		return nil, 0, time.Time{}, io.EOF
	}
	sec, frac := int64(r.bo.Uint32(h[0:])), int64(r.bo.Uint32(h[4:]))
	if !r.nano {
		frac *= 1000
	}
	return data, r.link, time.Unix(sec, frac), nil
}

func (r *Reader) read(n int) ([]byte, error) {
	if cap(r.buf) < n {
		r.buf = make([]byte, n)
	}
	b := r.buf[:n]
	_, err := io.ReadFull(r.r, b)
	return b, err
}

// nextNG reads pcapng blocks until one carries a packet.
func (r *Reader) nextNG() ([]byte, int, time.Time, error) {
	for {
		var h [8]byte
		if _, err := io.ReadFull(r.r, h[:]); err != nil {
			if err == io.ErrUnexpectedEOF {
				err = io.EOF
			}
			return nil, 0, time.Time{}, err
		}
		typ := binary.LittleEndian.Uint32(h[:])
		if typ == 0x0a0d0d0a { // section header: its byte order rules the section
			var m [4]byte
			if _, err := io.ReadFull(r.r, m[:]); err != nil {
				return nil, 0, time.Time{}, io.EOF
			}
			switch {
			case binary.LittleEndian.Uint32(m[:]) == 0x1a2b3c4d:
				r.bo = binary.LittleEndian
			case binary.BigEndian.Uint32(m[:]) == 0x1a2b3c4d:
				r.bo = binary.BigEndian
			default:
				return nil, 0, time.Time{}, ErrFormat
			}
			total := r.bo.Uint32(h[4:])
			if total < 28 || total > maxFrame {
				return nil, 0, time.Time{}, fmt.Errorf("damaged file: a %d-byte section header", total)
			}
			if _, err := r.read(int(total) - 12); err != nil {
				return nil, 0, time.Time{}, io.EOF
			}
			r.ifaces = r.ifaces[:0]
			continue
		}
		if r.bo == nil {
			return nil, 0, time.Time{}, ErrFormat
		}
		typ = r.bo.Uint32(h[:])
		total := r.bo.Uint32(h[4:])
		if total < 12 || total%4 != 0 || total > maxFrame {
			return nil, 0, time.Time{}, fmt.Errorf("damaged file: a %d-byte block", total)
		}
		body, err := r.read(int(total) - 8) // body and the trailing length
		if err != nil {
			return nil, 0, time.Time{}, io.EOF
		}
		body = body[:len(body)-4]
		switch typ {
		case 1: // interface description
			if len(body) < 8 {
				continue
			}
			r.ifaces = append(r.ifaces, iface{link: int(r.bo.Uint16(body)), units: tsUnits(r.bo, body[8:])})
		case 6: // enhanced packet
			if len(body) < 20 {
				continue
			}
			id := r.bo.Uint32(body)
			caplen := int(r.bo.Uint32(body[12:]))
			if int(id) >= len(r.ifaces) || 20+caplen > len(body) {
				continue
			}
			ifc := r.ifaces[id]
			ts := uint64(r.bo.Uint32(body[4:]))<<32 | uint64(r.bo.Uint32(body[8:]))
			r.last = when(ts, ifc.units)
			return body[20 : 20+caplen], ifc.link, r.last, nil
		case 3: // simple packet: interface 0, no time
			if len(body) < 4 || len(r.ifaces) == 0 {
				continue
			}
			n := int(r.bo.Uint32(body))
			if n > len(body)-4 {
				n = len(body) - 4
			}
			return body[4 : 4+n], r.ifaces[0].link, r.last, nil
		case 2: // packet (obsolete)
			if len(body) < 20 {
				continue
			}
			id := int(r.bo.Uint16(body))
			caplen := int(r.bo.Uint32(body[12:]))
			if id >= len(r.ifaces) || 20+caplen > len(body) {
				continue
			}
			ifc := r.ifaces[id]
			ts := uint64(r.bo.Uint32(body[4:]))<<32 | uint64(r.bo.Uint32(body[8:]))
			r.last = when(ts, ifc.units)
			return body[20 : 20+caplen], ifc.link, r.last, nil
		}
		// Anything else (name resolution, statistics, custom blocks) is
		// not traffic.
	}
}

// tsUnits reads an interface's if_tsresol option: timestamp units per
// second, a million unless it says otherwise.
func tsUnits(bo binary.ByteOrder, opts []byte) float64 {
	for len(opts) >= 4 {
		code, l := bo.Uint16(opts), int(bo.Uint16(opts[2:]))
		if code == 0 || 4+l > len(opts) {
			break
		}
		if code == 9 && l >= 1 {
			v := opts[4]
			if v&0x80 != 0 {
				return math.Pow(2, float64(v&0x7f))
			}
			return math.Pow(10, float64(v))
		}
		opts = opts[4+(l+3)&^3:]
	}
	return 1e6
}

func when(ts uint64, units float64) time.Time {
	if units == 1e6 {
		return time.UnixMicro(int64(ts))
	}
	if units == 1e9 {
		return time.Unix(0, int64(ts))
	}
	sec := math.Floor(float64(ts) / units)
	frac := float64(ts) - sec*units
	return time.Unix(int64(sec), int64(frac/units*1e9))
}
