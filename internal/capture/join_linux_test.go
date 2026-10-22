package capture

import (
	"net"
	"testing"

	"golang.org/x/net/ipv4"
)

func setMulticastLoopbackIf(t *testing.T, c net.PacketConn) {
	p := ipv4.NewPacketConn(c)
	lo, _ := net.InterfaceByName("lo")
	if err := p.SetMulticastInterface(lo); err != nil {
		t.Skip(err)
	}
	_ = p.SetMulticastLoopback(true)
}
