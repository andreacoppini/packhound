package mpegts

import (
	"testing"
)

func channel(m *Muxer) []byte {
	var pk [][]byte
	pk = append(pk, m.Section(0, PAT(1, 17472, 0x64))...)
	pk = append(pk, m.Section(0x64, PMT(17472, 0x65, []ES{
		{Type: 0x1b, PID: 0x65},
		{Type: 0x0f, PID: 0x66, Lang: "eng"},
		{Type: 0x06, PID: 0x67, Desc: []byte{0x6a, 1, 0}},
	}))...)
	pk = append(pk, m.Section(0x11, SDT(1, 0x233a, 17472, 0x19, "BBC", "BBC One HD"))...)
	sps := SPS(1920, 1080, true)
	es := append([]byte{0, 0, 0, 1, 0x09, 0xf0, 0, 0, 0, 1}, sps...)
	es = append(es, 0, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80)
	pk = append(pk, m.PES(0x65, 0xe0, es)...)
	var out []byte
	for _, p := range pk {
		out = append(out, p...)
	}
	return out
}

func TestAnalyzerReadsTables(t *testing.T) {
	a := NewAnalyzer()
	a.Feed(channel(NewMuxer()))
	if a.TSID != 1 {
		t.Fatalf("TSID %d", a.TSID)
	}
	if got := a.ServiceName(); got != "BBC One HD" {
		t.Fatalf("service %q", got)
	}
	sv := a.Services()[0]
	if sv.Provider != "BBC" || sv.Type != "HD TV" || sv.PMTPID != 0x64 || sv.PCRPID != 0x65 {
		t.Fatalf("service %+v", sv)
	}
	if got := a.VideoSummary(); got != "H.264 1920×1080i" {
		t.Fatalf("video %q", got)
	}
	kinds := map[uint16]string{}
	for _, p := range a.PIDs() {
		kinds[p.PID] = p.Kind + "/" + p.Lang
	}
	want := map[uint16]string{0: "PAT/", 0x11: "SDT / BAT/", 0x64: "PMT/", 0x65: "H.264 video/", 0x66: "AAC audio/eng", 0x67: "AC-3 audio/"}
	for pid, k := range want {
		if kinds[pid] != k {
			t.Errorf("PID 0x%x = %q, want %q", pid, kinds[pid], k)
		}
	}
	if a.CCErrors != 0 || a.SyncErrors != 0 {
		t.Fatalf("errors on a clean stream: cc %d sync %d", a.CCErrors, a.SyncErrors)
	}
}

func TestContinuityErrors(t *testing.T) {
	m := NewMuxer()
	a := NewAnalyzer()
	for i := 0; i < 20; i++ {
		a.Feed(channel(m))
	}
	if a.CCErrors != 0 {
		t.Fatalf("clean stream counted %d CC errors", a.CCErrors)
	}
	drop := 0
	m.SkipCC = func(pid uint16) bool {
		if pid == 0x65 && drop < 3 {
			drop++
			return true
		}
		return false
	}
	for i := 0; i < 5; i++ {
		a.Feed(channel(m))
	}
	if a.CCErrors != 3 || a.CCLastMinute() != 3 {
		t.Fatalf("CC errors %d (last minute %d), want 3", a.CCErrors, a.CCLastMinute())
	}
	a.Tick()
	if a.CCLastSecond() != 3 {
		t.Fatalf("last second %d", a.CCLastSecond())
	}
}

func TestDuplicatePacketIsNotAnError(t *testing.T) {
	m := NewMuxer()
	a := NewAnalyzer()
	pk := m.PES(0x100, 0xe0, make([]byte, 400))
	a.Feed(pk[0])
	a.Feed(pk[0]) // one legal duplicate
	a.Feed(pk[1])
	if a.CCErrors != 0 {
		t.Fatalf("duplicate counted as %d errors", a.CCErrors)
	}
}

func TestSyncLossResynchronises(t *testing.T) {
	m := NewMuxer()
	good := m.PES(0x100, 0xe0, make([]byte, 100))[0]
	b := append([]byte{1, 2, 3}, good...)
	a := NewAnalyzer()
	a.Feed(b)
	if a.SyncErrors == 0 || a.Packets != 1 {
		t.Fatalf("sync errors %d, packets %d", a.SyncErrors, a.Packets)
	}
}

func TestSPSSizes(t *testing.T) {
	for _, c := range []struct {
		w, h int
		i    bool
	}{{1920, 1080, true}, {1920, 1080, false}, {1280, 720, false}, {720, 576, true}, {3840, 2160, false}} {
		sps := SPS(c.w, c.h, c.i)
		w, h, i, ok := ParseSPS(sps[1:])
		if !ok || w != c.w || h != c.h || i != c.i {
			t.Errorf("%dx%d interlaced=%v read back as %dx%d %v ok=%v", c.w, c.h, c.i, w, h, i, ok)
		}
	}
}

func TestLooksLikeTS(t *testing.T) {
	m := NewMuxer()
	b := channel(m)
	if !LooksLikeTS(b) {
		t.Fatal("TS not recognised")
	}
	if LooksLikeTS(make([]byte, 188*7)) || LooksLikeTS(b[:100]) {
		t.Fatal("non-TS recognised")
	}
}
