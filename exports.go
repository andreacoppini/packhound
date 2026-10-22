package main

import (
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/andreacoppini/packhound/internal/monitor"
	"github.com/andreacoppini/packhound/internal/snmp"
)

// What the service hands to network management systems: the SNMP tree and
// the REST API. Both are built from the same monitor snapshot, so they never
// disagree with each other or with the console.

// ---- stream identity ----

// snmpIndex is a stream's row index in the SNMP table, after the
// InetAddress convention: address type (1 IPv4, 2 IPv6), address length,
// the address octets, then the port. 239.192.1.1:1234 is 1.4.239.192.1.1.1234,
// so a manager can name any stream's OID without walking the table.
func snmpIndex(r monitor.Row) snmp.OID {
	a, err := netip.ParseAddr(strings.SplitN(r.Addr, "/", 2)[0])
	if err != nil {
		return nil
	}
	b := a.AsSlice()
	idx := snmp.OID{1, uint32(len(b))}
	if a.Is6() {
		idx[0] = 2
	}
	for _, x := range b {
		idx = append(idx, uint32(x))
	}
	// Streams that are not UDP have no port; the protocol number stands in,
	// offset past the port range so the two can never collide.
	port := uint32(r.Port)
	if r.Proto != "UDP" {
		port = 65536 + protoNumber(r.Proto)
	}
	return append(idx, port)
}

func protoNumber(name string) uint32 {
	switch name {
	case "IGMP":
		return 2
	case "ICMPv6":
		return 58
	case "OSPF":
		return 89
	case "PIM":
		return 103
	case "VRRP":
		return 112
	case "EIGRP":
		return 88
	}
	var n uint32
	fmt.Sscanf(name, "IP %d", &n)
	return n
}

var statusCode = map[monitor.Status]int64{
	monitor.Receiving: 1, monitor.Degraded: 2, monitor.Lost: 3, monitor.Periodic: 4, monitor.Quiet: 5,
}

// ---- SNMP ----

// The tree under the base OID (default 1.3.6.1.4.1.8072.9999.9999.7):
//
//	base.1.N.0     scalars: version, stream counts, totals
//	base.2.1.C.I   the stream table: column C, stream index I (see snmpIndex)
//
// docs/PACKHOUND-MIB.txt describes every object.
const (
	colGroup = iota + 2
	colName
	colType
	colKind
	colSender
	colStatus
	colStatusText
	colBitRate
	colKbps
	colPacketRate
	colAvgSize
	colJitterUs
	colErrorsMin
	colSenderErrorsMin
	colSenders
	colPackets
	colOctets
	colLastSeen
	colProblem
)

// ascii keeps SNMP strings to plain ASCII, as DisplayString requires:
// managers show anything else as hex.
func ascii(s string) snmp.Value {
	s = strings.ReplaceAll(s, " · ", " - ")
	s = strings.ReplaceAll(s, "×", "x")
	b := make([]byte, 0, len(s))
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b = append(b, byte(r))
		} else {
			b = append(b, '?')
		}
	}
	return snmp.OctetString(string(b))
}

func (s *service) snmpTree() []snmp.Varbind {
	cfg := s.store.get()
	base, err := snmp.ParseOID(cfg.SNMP.BaseOID)
	if err != nil {
		base = snmp.MustOID(defaultBaseOID)
	}
	snap := s.eng.mon.Snapshot("", 60)
	st := s.eng.status()
	sum := summarise(snap, st)
	up := uint64(time.Since(s.started) / (10 * time.Millisecond))

	sys := snmp.MustOID("1.3.6.1.2.1.1")
	t := []snmp.Varbind{
		{OID: sys.Append(1, 0), Value: ascii(fmt.Sprintf("Packhound %s multicast monitor", version))},
		{OID: sys.Append(2, 0), Value: snmp.ObjectID(base)},
		{OID: sys.Append(3, 0), Value: snmp.TimeTicks(up)},
		{OID: sys.Append(4, 0), Value: ascii(cfg.SNMP.Contact)},
		{OID: sys.Append(5, 0), Value: ascii(s.hostname())},
		{OID: sys.Append(6, 0), Value: ascii(cfg.SNMP.Location)},
		{OID: sys.Append(7, 0), Value: snmp.Integer(72)},
	}
	listening := int64(2)
	if st.Running {
		listening = 1
	}
	g := base.Append(1)
	t = append(t,
		snmp.Varbind{OID: g.Append(1, 0), Value: ascii(version)},
		snmp.Varbind{OID: g.Append(2, 0), Value: snmp.Gauge32(uint64(sum.Streams))},
		snmp.Varbind{OID: g.Append(3, 0), Value: snmp.Gauge32(uint64(sum.Receiving))},
		snmp.Varbind{OID: g.Append(4, 0), Value: snmp.Gauge32(uint64(sum.Degraded))},
		snmp.Varbind{OID: g.Append(5, 0), Value: snmp.Gauge32(uint64(sum.Lost))},
		snmp.Varbind{OID: g.Append(6, 0), Value: snmp.Gauge32(uint64(sum.BitRate))},
		snmp.Varbind{OID: g.Append(7, 0), Value: snmp.Gauge32(uint64(sum.BitRate / 1000))},
		snmp.Varbind{OID: g.Append(8, 0), Value: snmp.Gauge32(uint64(math.Round(sum.PacketRate)))},
		snmp.Varbind{OID: g.Append(9, 0), Value: snmp.Integer(listening)},
		snmp.Varbind{OID: g.Append(10, 0), Value: snmp.Gauge32(sum.LocalDropsLastMinute)},
		snmp.Varbind{OID: g.Append(11, 0), Value: snmp.Gauge32(uint64(sum.MediaStreams))},
	)

	entry := base.Append(2, 1)
	for _, r := range snap.Rows {
		idx := snmpIndex(r)
		if idx == nil {
			continue
		}
		jit := uint64(0)
		if r.JitterMs > 0 {
			jit = uint64(r.JitterMs * 1000)
		}
		last := uint64(0)
		if !r.LastSeen.IsZero() && snap.Now.After(r.LastSeen) {
			last = uint64(snap.Now.Sub(r.LastSeen).Seconds())
		}
		col := func(c uint32, v snmp.Value) snmp.Varbind {
			return snmp.Varbind{OID: append(entry.Append(c), idx...), Value: v}
		}
		t = append(t,
			col(colGroup, ascii(r.Group)),
			col(colName, ascii(r.Name)),
			col(colType, ascii(r.Type)),
			col(colKind, ascii(string(r.Kind))),
			col(colSender, ascii(r.Sender)),
			col(colStatus, snmp.Integer(statusCode[r.Status])),
			col(colStatusText, ascii(string(r.Status))),
			col(colBitRate, snmp.Gauge32(uint64(r.BPS))),
			col(colKbps, snmp.Gauge32(uint64(r.BPS/1000))),
			col(colPacketRate, snmp.Gauge32(uint64(math.Round(r.PPS)))),
			col(colAvgSize, snmp.Gauge32(uint64(r.AvgSize))),
			col(colJitterUs, snmp.Gauge32(jit)),
			col(colErrorsMin, snmp.Gauge32(r.ErrorsLastMinute)),
			col(colSenderErrorsMin, snmp.Gauge32(r.SourceErrors)),
			col(colSenders, snmp.Gauge32(uint64(r.Senders))),
			col(colPackets, snmp.Counter64(r.Packets)),
			col(colOctets, snmp.Counter64(r.Bytes)),
			col(colLastSeen, snmp.Gauge32(last)),
			col(colProblem, ascii(r.Reason)),
		)
	}
	return t
}

// ---- summary ----

type summary struct {
	Version              string    `json:"version"`
	Hostname             string    `json:"hostname"`
	Time                 time.Time `json:"time"`
	Listening            bool      `json:"listening"`
	Mode                 string    `json:"mode"`
	Interface            string    `json:"interface"`
	Streams              int       `json:"streams"`
	MediaStreams         int       `json:"mediaStreams"`
	Receiving            int       `json:"receiving"`
	Degraded             int       `json:"degraded"`
	Lost                 int       `json:"lost"`
	BitRate              float64   `json:"bitRate"`
	PacketRate           float64   `json:"packetRate"`
	Senders              int       `json:"senders"`
	LocalDropsLastMinute uint64    `json:"localDropsLastMinute"`
	Alerts               int       `json:"alerts"`
}

func summarise(snap monitor.Snapshot, st engineStatus) summary {
	s := summary{
		Version: version, Time: snap.Now, Listening: st.Running, Mode: st.Mode, Interface: st.Iface,
		Streams: snap.Totals.Streams, BitRate: snap.Totals.BPS, PacketRate: snap.Totals.PPS,
		Senders: snap.Totals.Senders, LocalDropsLastMinute: snap.Totals.LocalDropsMin, Alerts: len(snap.Alerts),
	}
	for _, r := range snap.Rows {
		if r.Kind == monitor.KindVideo || r.Kind == monitor.KindAudio {
			s.MediaStreams++
		}
		switch r.Status {
		case monitor.Receiving:
			s.Receiving++
		case monitor.Degraded:
			s.Degraded++
		case monitor.Lost:
			s.Lost++
		}
	}
	return s
}

// ---- REST API ----

// apiStream is one stream as the API returns it. Field names are part of the
// API: add to them, never rename.
type apiStream struct {
	ID                     string    `json:"id"`
	Group                  string    `json:"group"`
	Address                string    `json:"address"`
	Port                   int       `json:"port"`
	Family                 int       `json:"family"`
	Protocol               string    `json:"protocol"`
	Kind                   string    `json:"kind"`
	Type                   string    `json:"type"`
	Name                   string    `json:"name"`
	Sender                 string    `json:"sender"`
	SenderName             string    `json:"senderName,omitempty"`
	Senders                int       `json:"senders"`
	Status                 string    `json:"status"`
	StatusCode             int64     `json:"statusCode"`
	Problem                string    `json:"problem,omitempty"`
	BitRate                float64   `json:"bitRate"`
	PacketRate             float64   `json:"packetRate"`
	AvgSize                int       `json:"avgSize"`
	JitterMs               *float64  `json:"jitterMs"`
	ErrorsLastMinute       uint64    `json:"errorsLastMinute"`
	SenderErrorsLastMinute uint64    `json:"senderErrorsLastMinute"`
	Packets                uint64    `json:"packets"`
	Bytes                  uint64    `json:"bytes"`
	FirstSeen              time.Time `json:"firstSeen"`
	LastSeen               time.Time `json:"lastSeen"`
	SNMPIndex              string    `json:"snmpIndex"`
	PlayURL                string    `json:"playURL,omitempty"`
	VLAN                   uint16    `json:"vlan,omitempty"`
}

func toAPI(r monitor.Row) apiStream {
	a := apiStream{
		ID: r.Group, Group: r.Group, Address: r.Addr, Port: r.Port, Family: r.Family, Protocol: r.Proto,
		Kind: kindName(r.Kind), Type: r.Type, Name: r.Name, Sender: r.Sender, SenderName: r.SenderName, Senders: r.Senders,
		Status: string(r.Status), StatusCode: statusCode[r.Status], Problem: r.Reason,
		BitRate: math.Round(r.BPS), PacketRate: math.Round(r.PPS*10) / 10, AvgSize: r.AvgSize,
		ErrorsLastMinute: r.ErrorsLastMinute, SenderErrorsLastMinute: r.SourceErrors,
		Packets: r.Packets, Bytes: r.Bytes, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen,
		SNMPIndex: snmpIndex(r).String(), PlayURL: r.PlayURL, VLAN: r.VLAN,
	}
	if r.JitterMs >= 0 {
		j := math.Round(r.JitterMs*100) / 100
		a.JitterMs = &j
	}
	return a
}

func kindName(k monitor.Kind) string {
	return map[monitor.Kind]string{
		monitor.KindVideo: "video", monitor.KindAudio: "audio", monitor.KindDiscovery: "discovery",
		monitor.KindTiming: "timing", monitor.KindNetwork: "network", monitor.KindUnknown: "unknown",
	}[k]
}

// handleAPI serves /api/v1/...
//
//	GET /api/v1/summary
//	GET /api/v1/streams[?kind=video&status=Degraded&family=4]
//	GET /api/v1/streams/{group}       e.g. 239.192.1.1:1234, [ff02::fb]:5353, 224.0.0.1
//	GET /api/v1/alerts[?since=RFC3339]
func (s *service) handleAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "the API is read-only", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	q := r.URL.Query()
	switch {
	case path == "summary":
		sum := summarise(s.eng.mon.Snapshot("", 60), s.eng.status())
		sum.Hostname = s.hostname()
		writeJSON(w, sum)
	case path == "streams":
		snap := s.eng.mon.Snapshot("", 60)
		out := []apiStream{}
		for _, row := range snap.Rows {
			a := toAPI(row)
			if k := q.Get("kind"); k != "" && !strings.EqualFold(k, a.Kind) {
				continue
			}
			if st := q.Get("status"); st != "" && !strings.EqualFold(st, a.Status) {
				continue
			}
			if f := q.Get("family"); f != "" && f != fmt.Sprint(a.Family) {
				continue
			}
			out = append(out, a)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Group < out[j].Group })
		writeJSON(w, map[string]any{"time": snap.Now, "streams": out})
	case strings.HasPrefix(path, "streams/"):
		id := strings.TrimPrefix(path, "streams/")
		snap := s.eng.mon.Snapshot("", 60)
		for _, row := range snap.Rows {
			if row.Group == id || row.Key == id || row.Addr == id {
				d := s.eng.mon.Snapshot(row.Key, 60).Detail
				out := map[string]any{"stream": toAPI(row)}
				if d != nil {
					out["detail"] = d.KV
					out["tables"] = d.Tables
					out["senders"] = d.Senders
				}
				writeJSON(w, out)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "{\"error\":\"no stream %q\"}\n", id)
	case path == "alerts":
		snap := s.eng.mon.Snapshot("", 60)
		alerts := snap.Alerts
		if v := q.Get("since"); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				writeErr(w, fmt.Errorf("since must be RFC 3339, as 2026-10-22T10:00:00Z"))
				return
			}
			var keep []monitor.Alert
			for _, a := range alerts {
				if a.Time.After(t) {
					keep = append(keep, a)
				}
			}
			alerts = keep
		}
		if alerts == nil {
			alerts = []monitor.Alert{}
		}
		writeJSON(w, map[string]any{"alerts": alerts})
	default:
		http.NotFound(w, r)
	}
}

// handleMetrics serves the same numbers in Prometheus' text format.
func (s *service) handleMetrics(w http.ResponseWriter, r *http.Request) {
	snap := s.eng.mon.Snapshot("", 60)
	sum := summarise(snap, s.eng.status())
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	var b strings.Builder
	g := func(name, help string, v float64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, v)
	}
	g("packhound_streams", "Streams seen.", float64(sum.Streams))
	g("packhound_streams_degraded", "Streams degraded now.", float64(sum.Degraded))
	g("packhound_streams_lost", "Streams lost now.", float64(sum.Lost))
	g("packhound_bit_rate", "Total multicast bit rate, bits per second.", sum.BitRate)
	g("packhound_local_drops_last_minute", "Packets this machine dropped in the last minute.", float64(sum.LocalDropsLastMinute))
	metric := func(name, typ, help string, val func(apiStream) float64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
		for _, row := range snap.Rows {
			a := toAPI(row)
			fmt.Fprintf(&b, "%s{group=%q,name=%q,kind=%q,type=%q} %g\n", name, a.Group, a.Name, a.Kind, a.Type, val(a))
		}
	}
	metric("packhound_stream_bit_rate", "gauge", "Bit rate, bits per second.", func(a apiStream) float64 { return a.BitRate })
	metric("packhound_stream_packet_rate", "gauge", "Packets per second.", func(a apiStream) float64 { return a.PacketRate })
	metric("packhound_stream_status", "gauge", "1 receiving, 2 degraded, 3 lost, 4 periodic, 5 quiet.", func(a apiStream) float64 { return float64(a.StatusCode) })
	metric("packhound_stream_errors_last_minute", "gauge", "Packets lost on the way in the last minute.", func(a apiStream) float64 { return float64(a.ErrorsLastMinute) })
	metric("packhound_stream_jitter_ms", "gauge", "Packet arrival jitter, milliseconds.", func(a apiStream) float64 {
		if a.JitterMs == nil {
			return 0
		}
		return *a.JitterMs
	})
	metric("packhound_stream_packets_total", "counter", "Packets received.", func(a apiStream) float64 { return float64(a.Packets) })
	metric("packhound_stream_bytes_total", "counter", "Bytes received.", func(a apiStream) float64 { return float64(a.Bytes) })
	_, _ = w.Write([]byte(b.String()))
}
