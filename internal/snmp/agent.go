package snmp

import (
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Varbind is one OID and its value.
type Varbind struct {
	OID   OID
	Value Value
}

// Source supplies the agent's whole tree, in any order. It is called at most
// once a second; walks in between are answered from the same copy, so a
// manager walking a table sees one consistent snapshot of it.
type Source func() []Varbind

// Config is what the agent answers to.
type Config struct {
	Community string         // read-only community; never empty
	Allow     []netip.Prefix // managers allowed to ask; empty allows everyone
}

// Agent answers SNMP requests on a UDP socket.
type Agent struct {
	src Source

	mu       sync.Mutex
	cfg      Config
	cache    []Varbind
	cachedAt time.Time

	conn *net.UDPConn

	// Requests is the number of requests answered; BadCommunity those
	// dropped for a wrong community or a manager not on the allow list.
	Requests, BadCommunity uint64
}

func NewAgent(cfg Config, src Source) *Agent {
	return &Agent{cfg: cfg, src: src}
}

// SetConfig changes the community and allow list for later requests.
func (a *Agent) SetConfig(cfg Config) {
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
}

// Listen binds the agent's socket; Serve then answers on it.
func (a *Agent) Listen(addr string) error {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	c, err := net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	a.conn = c
	return nil
}

// Serve answers requests until Close.
func (a *Agent) Serve() error {
	buf := make([]byte, 65535)
	for {
		n, from, err := a.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		if out := a.Handle(buf[:n], from.Addr().Unmap()); out != nil {
			_, _ = a.conn.WriteToUDPAddrPort(out, from)
		}
	}
}

func (a *Agent) Close() error {
	if a.conn == nil {
		return nil
	}
	return a.conn.Close()
}

func (a *Agent) tree() []Varbind {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cache == nil || time.Since(a.cachedAt) >= time.Second {
		t := a.src()
		sort.Slice(t, func(i, j int) bool { return t[i].OID.Compare(t[j].OID) < 0 })
		a.cache, a.cachedAt = t, time.Now()
	}
	return a.cache
}

// maxResponse bounds a response. GetBulk stops adding rows before it is
// reached; a Get whose answer would exceed it gets tooBig.
const maxResponse = 8192

// SNMP error statuses.
const (
	errNone        = 0
	errTooBig      = 1
	errNoSuchName  = 2
	errReadOnly    = 4
	errGenErr      = 5
	errNoAccess    = 6
	errNotWritable = 17
)

// Handle answers one request, or returns nil to drop it.
func (a *Agent) Handle(req []byte, from netip.Addr) []byte {
	r := &reader{b: req}
	msg, err := r.expect(tagSequence)
	if err != nil {
		return nil
	}
	m := &reader{b: msg}
	version, err := m.integer()
	if err != nil || (version != 0 && version != 1) {
		return nil // only v1 (0) and v2c (1)
	}
	comm, err := m.expect(tagOctets)
	if err != nil {
		return nil
	}

	a.mu.Lock()
	cfg := a.cfg
	allowed := len(cfg.Allow) == 0
	for _, p := range cfg.Allow {
		if p.Contains(from) {
			allowed = true
			break
		}
	}
	if !allowed || cfg.Community == "" || string(comm) != cfg.Community {
		a.BadCommunity++
		a.mu.Unlock()
		return nil // silence, as agents do for a wrong community
	}
	a.Requests++
	a.mu.Unlock()

	pduType, pdu, err := m.tlv()
	if err != nil {
		return nil
	}
	p := &reader{b: pdu}
	reqID, err1 := p.integer()
	f1, err2 := p.integer() // error status, or non-repeaters for GetBulk
	f2, err3 := p.integer() // error index, or max-repetitions
	vbl, err4 := p.expect(tagSequence)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return nil
	}
	var oids []OID
	vr := &reader{b: vbl}
	for len(vr.b) > 0 {
		vb, err := vr.expect(tagSequence)
		if err != nil {
			return nil
		}
		x := &reader{b: vb}
		oc, err := x.expect(tagOID)
		if err != nil {
			return nil
		}
		o, err := decodeOID(oc)
		if err != nil {
			return nil
		}
		oids = append(oids, o)
	}
	if len(oids) > 256 {
		return nil
	}

	v1 := version == 0
	var out []Varbind
	status, index := errNone, 0
	switch pduType {
	case pduGet:
		out, status, index = a.get(oids, v1)
	case pduGetNext:
		out, status, index = a.getNext(oids, v1)
	case pduGetBulk:
		if v1 {
			return nil
		}
		out = a.getBulk(oids, int(f1), int(f2))
	case pduSet:
		out = make([]Varbind, len(oids))
		for i, o := range oids {
			out[i] = Varbind{o, Value{tag: tagNull}}
		}
		status, index = errNoAccess, 1
		if v1 {
			status = errReadOnly
		}
	default:
		return nil
	}

	resp := encodeResponse(version, comm, reqID, status, index, out)
	if len(resp) > maxResponse && pduType != pduGetBulk {
		empty := make([]Varbind, len(oids))
		for i, o := range oids {
			empty[i] = Varbind{o, Value{tag: tagNull}}
		}
		resp = encodeResponse(version, comm, reqID, errTooBig, 0, empty)
	}
	return resp
}

func (a *Agent) get(oids []OID, v1 bool) ([]Varbind, int, int) {
	t := a.tree()
	out := make([]Varbind, len(oids))
	for i, o := range oids {
		j := sort.Search(len(t), func(k int) bool { return t[k].OID.Compare(o) >= 0 })
		if j < len(t) && t[j].OID.Compare(o) == 0 && !(v1 && t[j].Value.tag == tagCounter64) {
			out[i] = t[j]
			continue
		}
		if v1 {
			return nullBinds(oids), errNoSuchName, i + 1
		}
		tag := byte(tagNoSuchObj)
		// The object exists but not this instance of it: a neighbour in the
		// tree shares everything but the last arc.
		obj := o[:max(len(o)-1, 1)]
		near := func(k int) bool { return k >= 0 && k < len(t) && len(t[k].OID) == len(o) && t[k].OID.HasPrefix(obj) }
		if near(j) || near(j-1) {
			tag = tagNoSuchInst
		}
		out[i] = Varbind{o, Value{tag: tag}}
	}
	return out, errNone, 0
}

// next finds the first value after o; v1 cannot carry Counter64, so a v1
// walk steps over them (RFC 3584).
func next(t []Varbind, o OID, v1 bool) (Varbind, bool) {
	j := sort.Search(len(t), func(k int) bool { return t[k].OID.Compare(o) > 0 })
	for ; j < len(t); j++ {
		if v1 && t[j].Value.tag == tagCounter64 {
			continue
		}
		return t[j], true
	}
	return Varbind{}, false
}

func (a *Agent) getNext(oids []OID, v1 bool) ([]Varbind, int, int) {
	t := a.tree()
	out := make([]Varbind, len(oids))
	for i, o := range oids {
		vb, ok := next(t, o, v1)
		if !ok {
			if v1 {
				return nullBinds(oids), errNoSuchName, i + 1
			}
			vb = Varbind{o, Value{tag: tagEndOfView}}
		}
		out[i] = vb
	}
	return out, errNone, 0
}

func (a *Agent) getBulk(oids []OID, nonRep, maxRep int) []Varbind {
	t := a.tree()
	nonRep = min(max(nonRep, 0), len(oids))
	maxRep = min(max(maxRep, 0), 1000)
	var out []Varbind
	size := 0
	add := func(vb Varbind) bool {
		n := len(vb.Value.encode(nil)) + len(encodeOID(vb.OID)) + 8
		if size+n > maxResponse-200 && len(out) > 0 {
			return false
		}
		size += n
		out = append(out, vb)
		return true
	}
	for _, o := range oids[:nonRep] {
		vb, ok := next(t, o, false)
		if !ok {
			vb = Varbind{o, Value{tag: tagEndOfView}}
		}
		if !add(vb) {
			return out
		}
	}
	cur := append([]OID(nil), oids[nonRep:]...)
	for r := 0; r < maxRep && len(cur) > 0; r++ {
		allEnd := true
		for i, o := range cur {
			vb, ok := next(t, o, false)
			if !ok {
				vb = Varbind{o, Value{tag: tagEndOfView}}
			} else {
				allEnd = false
			}
			if !add(vb) {
				return out
			}
			cur[i] = vb.OID
		}
		if allEnd {
			break
		}
	}
	return out
}

func nullBinds(oids []OID) []Varbind {
	out := make([]Varbind, len(oids))
	for i, o := range oids {
		out[i] = Varbind{o, Value{tag: tagNull}}
	}
	return out
}

func encodeResponse(version int64, comm []byte, reqID int64, status, index int, vbs []Varbind) []byte {
	var list []byte
	for _, vb := range vbs {
		inner := appendTLV(nil, tagOID, encodeOID(vb.OID))
		inner = vb.Value.encode(inner)
		list = appendTLV(list, tagSequence, inner)
	}
	var pdu []byte
	pdu = appendTLV(pdu, tagInteger, encodeInt(reqID))
	pdu = appendTLV(pdu, tagInteger, encodeInt(int64(status)))
	pdu = appendTLV(pdu, tagInteger, encodeInt(int64(index)))
	pdu = appendTLV(pdu, tagSequence, list)
	var msg []byte
	msg = appendTLV(msg, tagInteger, encodeInt(version))
	msg = appendTLV(msg, tagOctets, comm)
	msg = appendTLV(msg, pduResponse, pdu)
	return appendTLV(nil, tagSequence, msg)
}
