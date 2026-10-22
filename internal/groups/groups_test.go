package groups

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	gs, err := Parse(`239.10.1.1-3:5000
239.10.2.0/30:5004, [ff02::fb]:5353   # mDNS
239.10.1.2:5000
239.20.0.254-239.20.1.1:6000`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, g := range gs {
		got = append(got, g.String())
	}
	want := "239.10.1.1:5000 239.10.1.2:5000 239.10.1.3:5000 239.10.2.0:5004 239.10.2.1:5004 239.10.2.2:5004 239.10.2.3:5004 [ff02::fb]:5353 239.20.0.254:6000 239.20.0.255:6000 239.20.1.0:6000 239.20.1.1:6000"
	if strings.Join(got, " ") != want {
		t.Fatalf("got  %s\nwant %s", strings.Join(got, " "), want)
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"239.1.1.1", "10.0.0.1:5000", "239.1.1.1:0", "ff02::fb:5353", "239.1.1.9-1:5000", "239.0.0.0/8:5000", "nonsense:5"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if _, err := Parse("239.1.1.1:5000\n10.0.0.1:5000\nbad"); err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("errors should name every bad line: %v", err)
	}
}

func TestCommonParses(t *testing.T) {
	gs, err := Parse(Common)
	if err != nil || len(gs) != 8 {
		t.Fatalf("%d groups, %v", len(gs), err)
	}
}
