package monitor

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/andreacoppini/packhound/internal/pkt"
)

// ptpV1Sync builds a PTPv1 Sync message as a Dante clock leader sends it.
func ptpV1Sync(uuid [6]byte) []byte {
	b := make([]byte, 124)
	binary.BigEndian.PutUint16(b[0:], 1) // versionPTP
	binary.BigEndian.PutUint16(b[2:], 1) // versionNetwork
	copy(b[4:], "_DFLT")
	b[20] = 1 // event message
	b[21] = 1 // Ethernet
	copy(b[22:28], uuid[:])
	b[32] = 0 // control: Sync
	b[53] = 1
	copy(b[54:60], uuid[:]) // grandmaster: itself
	b[67] = 4               // stratum
	copy(b[68:72], "DFLT")
	b[77] = 1    // preferred
	b[83] = 0xfe // sync interval 2^-2 s
	binary.BigEndian.PutUint16(b[90:], 0)
	return b
}

// dnsResponse builds an mDNS answer: a PTR to an instance, its SRV, and an A
// record for the host.
func dnsResponse(stype, instance, host string, addr netip.Addr) []byte {
	name := func(b []byte, n string) []byte {
		for _, l := range strings.Split(n, ".") {
			b = append(b, byte(len(l)))
			b = append(b, l...)
		}
		return append(b, 0)
	}
	rr := func(b []byte, n string, typ uint16, rdata []byte) []byte {
		b = name(b, n)
		b = binary.BigEndian.AppendUint16(b, typ)
		b = binary.BigEndian.AppendUint16(b, 0x8001)
		b = binary.BigEndian.AppendUint32(b, 120)
		b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
		return append(b, rdata...)
	}
	full := instance + "." + stype + ".local"
	b := []byte{0, 0, 0x84, 0, 0, 0, 0, 3, 0, 0, 0, 0}
	b = rr(b, stype+".local", 12, name(nil, full))
	b = rr(b, full, 33, name([]byte{0, 0, 0, 0, 0x11, 0x2c}, host+".local"))
	b = rr(b, host+".local", 1, addr.AsSlice())
	return b
}

func udpPacket(t time.Time, src, dst string, sport, dport uint16, payload []byte) *pkt.Packet {
	return &pkt.Packet{Time: t, Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst), Proto: pkt.ProtoUDP,
		SrcPort: sport, DstPort: dport, IPLen: 28 + len(payload), Payload: payload}
}

func TestDante(t *testing.T) {
	m := New(DefaultConfig())
	dev := netip.MustParseAddr("10.20.6.40")

	// The device announces itself and two of its channels.
	m.Ingest(udpPacket(t0, "10.20.6.40", "224.0.0.251", 5353, 5353, dnsResponse("_netaudio-arc._udp", "Stagebox-1", "Stagebox-1", dev)))
	m.Ingest(udpPacket(t0, "10.20.6.40", "224.0.0.251", 5353, 5353, dnsResponse("_netaudio-chan._udp", "Mic 1@Stagebox-1", "Stagebox-1", dev)))
	m.Ingest(udpPacket(t0, "10.20.6.40", "224.0.0.251", 5353, 5353, dnsResponse("_netaudio-chan._udp", "Mic 2@Stagebox-1", "Stagebox-1", dev)))
	// It leads the PTPv1 clock, and sends a multicast flow.
	m.Ingest(udpPacket(t0, "10.20.6.40", "224.0.1.129", 319, 319, ptpV1Sync([6]byte{0x00, 0x1d, 0xc1, 0x0a, 0x44, 0x12})))
	for i := 0; i < 10; i++ {
		m.Ingest(udpPacket(t0.Add(time.Duration(i)*time.Millisecond), "10.20.6.40", "239.255.10.20", 4321, 4321, make([]byte, 300)))
	}
	m.Tick(t0.Add(time.Second))

	rows := map[string]Row{}
	for _, r := range m.Snapshot("", 60).Rows {
		rows[r.Group] = r
	}

	flow := rows["239.255.10.20:4321"]
	if flow.Kind != KindAudio || flow.Name != "Stagebox-1 · Dante multicast flow" || flow.SenderName != "Stagebox-1" {
		t.Errorf("flow: kind %s, name %q, sender name %q", flow.Kind, flow.Name, flow.SenderName)
	}

	mdns := rows["224.0.0.251:5353"]
	if !strings.HasSuffix(mdns.Name, " · 1 Dante device") {
		t.Errorf("mDNS name %q", mdns.Name)
	}
	d := m.Snapshot(mdns.Key, 60).Detail
	var devices *Table
	for i := range d.Tables {
		if d.Tables[i].Title == "Dante devices" {
			devices = &d.Tables[i]
		}
	}
	if devices == nil || len(devices.Rows) != 1 || devices.Rows[0][0] != "Stagebox-1" || devices.Rows[0][2] != "10.20.6.40" || devices.Rows[0][3] != "2" {
		t.Errorf("Dante devices table: %+v", devices)
	}

	ptp := rows["224.0.1.129:319"]
	if ptp.Name != "PTPv1 (Dante) · clock leader 00:1d:c1:0a:44:12" {
		t.Errorf("PTP name %q", ptp.Name)
	}
	kv := map[string]string{}
	for _, x := range m.Snapshot(ptp.Key, 60).Detail.KV {
		kv[x.K] = x.V
	}
	if kv["PTPv1 subdomain"] != "_DFLT" || kv["PTPv1 clock leader"] != "00:1d:c1:0a:44:12 at 10.20.6.40 (Stagebox-1)" ||
		kv["Leader stratum / identifier"] != "4 / DFLT" || kv["PTPv1 sync interval"] != "0.25 s" || kv["Leader"] != "preferred" {
		t.Errorf("PTPv1 detail: %v", kv)
	}
}
