// Package snmp is a small read-only SNMP agent: v1 and v2c, Get, GetNext
// and GetBulk, over a tree of values the caller supplies. It is what network
// managers such as The Dude poll, and needs no net-snmp on the machine.
package snmp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// BER tags used by SNMP.
const (
	tagInteger    = 0x02
	tagOctets     = 0x04
	tagNull       = 0x05
	tagOID        = 0x06
	tagSequence   = 0x30
	tagIPAddress  = 0x40
	tagCounter32  = 0x41
	tagGauge32    = 0x42
	tagTimeTicks  = 0x43
	tagCounter64  = 0x46
	tagNoSuchObj  = 0x80
	tagNoSuchInst = 0x81
	tagEndOfView  = 0x82

	pduGet      = 0xa0
	pduGetNext  = 0xa1
	pduResponse = 0xa2
	pduSet      = 0xa3
	pduTrapV1   = 0xa4
	pduGetBulk  = 0xa5
)

// OID is an object identifier.
type OID []uint32

// ParseOID reads "1.3.6.1.2.1" (a leading dot is allowed).
func ParseOID(s string) (OID, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), ".")
	if s == "" {
		return nil, errors.New("empty OID")
	}
	parts := strings.Split(s, ".")
	o := make(OID, len(parts))
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bad OID %q", s)
		}
		o[i] = uint32(n)
	}
	if len(o) < 2 || o[0] > 2 {
		return nil, fmt.Errorf("bad OID %q", s)
	}
	return o, nil
}

func MustOID(s string) OID {
	o, err := ParseOID(s)
	if err != nil {
		panic(err)
	}
	return o
}

func (o OID) String() string {
	var b strings.Builder
	for i, n := range o {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(uint64(n), 10))
	}
	return b.String()
}

// Append returns o followed by more, without sharing o's backing array.
func (o OID) Append(more ...uint32) OID {
	out := make(OID, 0, len(o)+len(more))
	return append(append(out, o...), more...)
}

// Compare orders OIDs lexicographically, as SNMP walks them.
func (o OID) Compare(p OID) int {
	for i := 0; i < len(o) && i < len(p); i++ {
		switch {
		case o[i] < p[i]:
			return -1
		case o[i] > p[i]:
			return 1
		}
	}
	switch {
	case len(o) < len(p):
		return -1
	case len(o) > len(p):
		return 1
	}
	return 0
}

// HasPrefix reports whether o lies under p.
func (o OID) HasPrefix(p OID) bool {
	return len(o) >= len(p) && o[:len(p)].Compare(p) == 0
}

// Value is an SNMP value.
type Value struct {
	tag   byte
	i     int64
	u     uint64
	bytes []byte
	oid   OID
}

func Integer(v int64) Value      { return Value{tag: tagInteger, i: v} }
func OctetString(s string) Value { return Value{tag: tagOctets, bytes: []byte(s)} }
func Counter32(v uint64) Value   { return Value{tag: tagCounter32, u: v & 0xffffffff} }
func Counter64(v uint64) Value   { return Value{tag: tagCounter64, u: v} }
func TimeTicks(v uint64) Value   { return Value{tag: tagTimeTicks, u: v & 0xffffffff} }
func ObjectID(o OID) Value       { return Value{tag: tagOID, oid: o} }

// Gauge32 saturates rather than wrapping: a gauge past its range should
// read as full, not as a small number.
func Gauge32(v uint64) Value {
	if v > 0xffffffff {
		v = 0xffffffff
	}
	return Value{tag: tagGauge32, u: v}
}

// String renders a value for logs and tests.
func (v Value) String() string {
	switch v.tag {
	case tagInteger:
		return strconv.FormatInt(v.i, 10)
	case tagOctets:
		return strconv.Quote(string(v.bytes))
	case tagOID:
		return v.oid.String()
	case tagNull:
		return "NULL"
	case tagNoSuchObj:
		return "noSuchObject"
	case tagNoSuchInst:
		return "noSuchInstance"
	case tagEndOfView:
		return "endOfMibView"
	}
	return strconv.FormatUint(v.u, 10)
}

// ---- encoding ----

func appendLength(b []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(b, byte(n))
	case n < 0x100:
		return append(b, 0x81, byte(n))
	case n < 0x10000:
		return append(b, 0x82, byte(n>>8), byte(n))
	}
	return append(b, 0x83, byte(n>>16), byte(n>>8), byte(n))
}

func appendTLV(b []byte, tag byte, content []byte) []byte {
	b = append(b, tag)
	b = appendLength(b, len(content))
	return append(b, content...)
}

func encodeInt(v int64) []byte {
	var out []byte
	for {
		out = append([]byte{byte(v)}, out...)
		if (v >= -128 && v < 128) || len(out) == 8 {
			break
		}
		v >>= 8
	}
	return out
}

func encodeUint(v uint64) []byte {
	out := []byte{byte(v)}
	for v >>= 8; v > 0; v >>= 8 {
		out = append([]byte{byte(v)}, out...)
	}
	if out[0]&0x80 != 0 { // keep it positive
		out = append([]byte{0}, out...)
	}
	return out
}

func encodeOID(o OID) []byte {
	if len(o) < 2 {
		return []byte{0}
	}
	out := []byte{byte(o[0]*40 + o[1])}
	for _, n := range o[2:] {
		var tmp [5]byte
		i := len(tmp) - 1
		tmp[i] = byte(n & 0x7f)
		for n >>= 7; n > 0; n >>= 7 {
			i--
			tmp[i] = byte(n&0x7f) | 0x80
		}
		out = append(out, tmp[i:]...)
	}
	return out
}

func (v Value) encode(b []byte) []byte {
	switch v.tag {
	case tagInteger:
		return appendTLV(b, v.tag, encodeInt(v.i))
	case tagOctets, tagIPAddress:
		return appendTLV(b, v.tag, v.bytes)
	case tagOID:
		return appendTLV(b, v.tag, encodeOID(v.oid))
	case tagNull, tagNoSuchObj, tagNoSuchInst, tagEndOfView:
		return append(b, v.tag, 0)
	}
	return appendTLV(b, v.tag, encodeUint(v.u))
}

// ---- decoding ----

var errBER = errors.New("malformed BER")

type reader struct{ b []byte }

func (r *reader) tlv() (tag byte, content []byte, err error) {
	if len(r.b) < 2 {
		return 0, nil, errBER
	}
	tag = r.b[0]
	n := int(r.b[1])
	off := 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 3 || len(r.b) < 2+k {
			return 0, nil, errBER
		}
		n = 0
		for i := 0; i < k; i++ {
			n = n<<8 | int(r.b[2+i])
		}
		off += k
	}
	if len(r.b) < off+n {
		return 0, nil, errBER
	}
	content = r.b[off : off+n]
	r.b = r.b[off+n:]
	return tag, content, nil
}

func (r *reader) expect(want byte) ([]byte, error) {
	tag, c, err := r.tlv()
	if err != nil {
		return nil, err
	}
	if tag != want {
		return nil, fmt.Errorf("expected tag 0x%02x, got 0x%02x", want, tag)
	}
	return c, nil
}

func (r *reader) integer() (int64, error) {
	c, err := r.expect(tagInteger)
	if err != nil {
		return 0, err
	}
	if len(c) == 0 || len(c) > 8 {
		return 0, errBER
	}
	v := int64(int8(c[0]))
	for _, x := range c[1:] {
		v = v<<8 | int64(x)
	}
	return v, nil
}

func decodeOID(c []byte) (OID, error) {
	if len(c) == 0 {
		return nil, errBER
	}
	o := OID{uint32(c[0]) / 40, uint32(c[0]) % 40}
	if c[0] >= 80 {
		o = OID{2, uint32(c[0]) - 80}
	}
	var n uint32
	for i, x := range c[1:] {
		if n > 0x1ffffff {
			return nil, errBER
		}
		n = n<<7 | uint32(x&0x7f)
		if x&0x80 == 0 {
			o = append(o, n)
			n = 0
		} else if i == len(c)-2 {
			return nil, errBER
		}
		if len(o) > 128 {
			return nil, errBER
		}
	}
	return o, nil
}
