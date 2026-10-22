package snmp

import (
	"net/netip"
	"testing"
)

func testTree() []Varbind {
	return []Varbind{
		{MustOID("1.3.6.1.2.1.1.5.0"), OctetString("packhound")},
		{MustOID("1.3.6.1.2.1.1.1.0"), OctetString("Packhound test")},
		{MustOID("1.3.6.1.4.1.9.1.1.0"), Gauge32(42)},
		{MustOID("1.3.6.1.4.1.9.1.2.0"), Counter64(1 << 40)},
		{MustOID("1.3.6.1.4.1.9.1.3.0"), Integer(-5)},
	}
}

// request builds a request the way a manager would.
func request(version int64, comm string, pdu byte, a, b int64, oids ...string) []byte {
	var list []byte
	for _, s := range oids {
		inner := appendTLV(nil, tagOID, encodeOID(MustOID(s)))
		inner = append(inner, tagNull, 0)
		list = appendTLV(list, tagSequence, inner)
	}
	var p []byte
	p = appendTLV(p, tagInteger, encodeInt(7))
	p = appendTLV(p, tagInteger, encodeInt(a))
	p = appendTLV(p, tagInteger, encodeInt(b))
	p = appendTLV(p, tagSequence, list)
	var m []byte
	m = appendTLV(m, tagInteger, encodeInt(version))
	m = appendTLV(m, tagOctets, []byte(comm))
	m = appendTLV(m, pdu, p)
	return appendTLV(nil, tagSequence, m)
}

type response struct {
	status, index int64
	vbs           []string // "oid=value"
}

func parse(t *testing.T, b []byte) response {
	t.Helper()
	if b == nil {
		t.Fatal("no response")
	}
	r := &reader{b: b}
	msg, _ := r.expect(tagSequence)
	m := &reader{b: msg}
	m.integer()
	m.expect(tagOctets)
	pdu, err := m.expect(pduResponse)
	if err != nil {
		t.Fatal(err)
	}
	p := &reader{b: pdu}
	var out response
	p.integer()
	out.status, _ = p.integer()
	out.index, _ = p.integer()
	vbl, _ := p.expect(tagSequence)
	vr := &reader{b: vbl}
	for len(vr.b) > 0 {
		vb, _ := vr.expect(tagSequence)
		x := &reader{b: vb}
		oc, _ := x.expect(tagOID)
		o, _ := decodeOID(oc)
		tag, c, _ := x.tlv()
		v := Value{tag: tag}
		switch tag {
		case tagInteger:
			x2 := &reader{b: appendTLV(nil, tagInteger, c)}
			v.i, _ = x2.integer()
		case tagOctets:
			v.bytes = c
		default:
			for _, y := range c {
				v.u = v.u<<8 | uint64(y)
			}
		}
		out.vbs = append(out.vbs, o.String()+"="+v.String())
	}
	return out
}

var me = netip.MustParseAddr("10.0.0.5")

func TestGetAndWalk(t *testing.T) {
	a := NewAgent(Config{Community: "public"}, testTree)
	r := parse(t, a.Handle(request(1, "public", pduGet, 0, 0, "1.3.6.1.2.1.1.5.0", "1.3.6.1.4.1.9.1.3.0", "1.3.6.1.4.1.9.1.1.5", "1.3.6.1.9"), me))
	want := []string{`1.3.6.1.2.1.1.5.0="packhound"`, "1.3.6.1.4.1.9.1.3.0=-5", "1.3.6.1.4.1.9.1.1.5=noSuchInstance", "1.3.6.1.9=noSuchObject"}
	for i := range want {
		if r.vbs[i] != want[i] {
			t.Errorf("get %d: %s, want %s", i, r.vbs[i], want[i])
		}
	}
	r = parse(t, a.Handle(request(1, "public", pduGetNext, 0, 0, "1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.9.1.3.0"), me))
	if r.vbs[0] != `1.3.6.1.2.1.1.5.0="packhound"` || r.vbs[1] != "1.3.6.1.4.1.9.1.3.0=endOfMibView" {
		t.Fatalf("getnext %v", r.vbs)
	}
	r = parse(t, a.Handle(request(1, "public", pduGetBulk, 0, 10, "1.3.6.1.4.1.9"), me))
	if len(r.vbs) != 4 || r.vbs[1] != "1.3.6.1.4.1.9.1.2.0=1099511627776" || r.vbs[3] != "1.3.6.1.4.1.9.1.3.0=endOfMibView" {
		t.Fatalf("bulk %v", r.vbs)
	}
}

func TestV1(t *testing.T) {
	a := NewAgent(Config{Community: "public"}, testTree)
	// A v1 walk steps over Counter64.
	r := parse(t, a.Handle(request(0, "public", pduGetNext, 0, 0, "1.3.6.1.4.1.9.1.1.0"), me))
	if r.vbs[0] != "1.3.6.1.4.1.9.1.3.0=-5" {
		t.Fatalf("v1 getnext %v", r.vbs)
	}
	r = parse(t, a.Handle(request(0, "public", pduGet, 0, 0, "1.3.6.1.4.1.9.1.9.0"), me))
	if r.status != errNoSuchName || r.index != 1 {
		t.Fatalf("v1 missing: status %d index %d", r.status, r.index)
	}
	if a.Handle(request(0, "public", pduGetBulk, 0, 5, "1.3"), me) != nil {
		t.Fatal("v1 GetBulk answered")
	}
}

func TestAccess(t *testing.T) {
	a := NewAgent(Config{Community: "s3cret", Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}, testTree)
	if a.Handle(request(1, "public", pduGet, 0, 0, "1.3.6.1.2.1.1.5.0"), me) != nil {
		t.Fatal("wrong community answered")
	}
	if a.Handle(request(1, "s3cret", pduGet, 0, 0, "1.3.6.1.2.1.1.5.0"), netip.MustParseAddr("192.168.1.1")) != nil {
		t.Fatal("manager outside the allow list answered")
	}
	r := parse(t, a.Handle(request(1, "s3cret", pduSet, 0, 0, "1.3.6.1.2.1.1.5.0"), me))
	if r.status != errNoAccess {
		t.Fatalf("set status %d", r.status)
	}
	if a.Handle([]byte{0x30, 0x84, 0xff}, me) != nil || a.Handle(nil, me) != nil {
		t.Fatal("garbage answered")
	}
}

func TestEncoding(t *testing.T) {
	for _, s := range []string{"1.3.6.1.4.1.8072.9999.9999.1.2.1.5.1.4.239.192.1.1.1234", "1.3.6", "0.0"} {
		o, err := decodeOID(encodeOID(MustOID(s)))
		if err != nil || o.String() != s {
			t.Errorf("%s round-tripped as %s (%v)", s, o, err)
		}
	}
	for _, v := range []int64{0, 1, 127, 128, 255, 256, -1, -128, -129, 1 << 40} {
		r := &reader{b: appendTLV(nil, tagInteger, encodeInt(v))}
		if got, _ := r.integer(); got != v {
			t.Errorf("%d round-tripped as %d", v, got)
		}
	}
}
