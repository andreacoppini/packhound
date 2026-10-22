//go:build linux

package capture

import (
	"net"
	"testing"
	"time"

	"github.com/andreacoppini/packhound/internal/groups"
)

// Several groups on one port, as IPTV head-ends send them: each joined
// group must report only its own datagrams. Go binds multicast listeners to
// the wildcard, and Linux by default gives every such socket every group.
func TestJoinedGroupsStayApart(t *testing.T) {
	lo, err := FindInterface("lo")
	if err != nil {
		t.Skip("no loopback interface named lo")
	}
	gs, _ := groups.Parse("239.199.7.1:47123\n239.199.7.2:47123")
	j, err := OpenJoin(lo, gs)
	if err != nil {
		t.Skipf("cannot join on loopback here: %v", err)
	}
	defer j.Close()

	out, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	setMulticastLoopbackIf(t, out)
	for i := 0; i < 5; i++ {
		out.WriteTo([]byte("one"), &net.UDPAddr{IP: net.ParseIP("239.199.7.1"), Port: 47123})
		out.WriteTo([]byte("two"), &net.UDPAddr{IP: net.ParseIP("239.199.7.2"), Port: 47123})
	}

	// Read for a while rather than stopping at ten: a socket that also gets
	// the other group's datagrams shows up as extra arrivals.
	frames := make(chan string, 64)
	go func() {
		for {
			f, err := j.Next()
			if err != nil {
				return
			}
			frames <- f.Pkt.Dst.String() + " " + string(f.Pkt.Payload)
		}
	}()
	got := map[string]int{}
	deadline := time.After(700 * time.Millisecond)
collect:
	for {
		select {
		case k := <-frames:
			got[k]++
		case <-deadline:
			break collect
		}
	}
	if len(got) == 0 {
		t.Skip("multicast does not loop back here")
	}
	for k, n := range got {
		if n != 5 {
			t.Fatalf("each datagram should arrive once, under its own group; got %v (%s)", got, k)
		}
	}
	if len(got) != 2 {
		t.Fatalf("datagrams under the wrong group: %v", got)
	}
}
