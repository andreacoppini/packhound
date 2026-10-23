// Package capture gets multicast traffic off a network interface, in one of
// two ways:
//
//   - Live capture sees every multicast frame the port receives, whether or
//     not this machine joined the group, including protocols that never reach
//     a socket (IGMP, VRRP, MLD). It needs privileges: root on Linux and macOS,
//     and Npcap on Windows. No C compiler is involved on any platform: Linux
//     uses an AF_PACKET socket, macOS a BPF device, and Windows loads Npcap's
//     wpcap.dll at run time.
//   - Joining opens ordinary UDP sockets and joins the listed groups. It needs
//     nothing installed and no privileges, but only sees those groups, and
//     only their UDP payloads.
//
// Joining is also useful alongside live capture: the join is what makes a
// snooping switch forward a group to this port at all.
package capture

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"golang.org/x/net/bpf"

	"github.com/andreacoppini/packhound/internal/pkt"
)

// Frame is one unit of traffic from a source.
type Frame struct {
	// Data is the raw frame, of link type Link. It aliases the source's
	// buffer and is only valid until the next call to Next.
	Data []byte
	Link int
	Time time.Time
	// Pkt is set instead of Data by sources that deliver datagrams
	// already decoded (joined sockets).
	Pkt *pkt.Packet
}

// Source delivers traffic until it is closed.
type Source interface {
	// Next blocks for the next frame. After Close it returns ErrClosed.
	Next() (Frame, error)
	Close() error
}

// Dropper is implemented by sources that know how many packets were lost on
// this machine, before Packhound could read them: the OS or capture driver's
// buffer overflowed. Such losses show up as errors on streams that are in
// fact fine on the wire, so they are reported apart.
type Dropper interface {
	Dropped() uint64 // since the source opened
}

// ErrClosed is returned by Next once the source has been closed.
var ErrClosed = errors.New("capture closed")

// Interface is a network interface traffic can be taken from.
type Interface struct {
	Name      string   `json:"name"`    // as the OS names it (eth0, en0, "Ethernet 2")
	Display   string   `json:"display"` // for a menu: name and addresses
	Index     int      `json:"index"`
	Addrs     []string `json:"addrs"`
	Up        bool     `json:"up"`
	Multicast bool     `json:"multicast"`
	Loopback  bool     `json:"loopback"`
	device    string   // what the capture driver calls it, where that differs
}

// Interfaces lists the interfaces, the likeliest choice first: up, not
// loopback, with an IPv4 address.
func Interfaces() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, ni := range ifs {
		it := Interface{
			Name:      ni.Name,
			Index:     ni.Index,
			Up:        ni.Flags&net.FlagUp != 0,
			Multicast: ni.Flags&net.FlagMulticast != 0,
			Loopback:  ni.Flags&net.FlagLoopback != 0,
		}
		addrs, _ := ni.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				it.Addrs = append(it.Addrs, n.IP.String())
			}
		}
		it.Display = displayName(it)
		out = append(out, it)
	}
	platformNames(out)
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) > rank(out[j]) })
	return out, nil
}

func rank(i Interface) int {
	r := 0
	if i.Up {
		r += 4
	}
	if !i.Loopback {
		r += 2
	}
	for _, a := range i.Addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			r++
			break
		}
	}
	return r
}

func displayName(i Interface) string {
	s := i.Name
	for _, a := range i.Addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			s += " · " + a
			break
		}
	}
	if !i.Up {
		s += " (down)"
	}
	return s
}

// FindInterface looks an interface up by name or index.
func FindInterface(name string) (Interface, error) {
	ifs, err := Interfaces()
	if err != nil {
		return Interface{}, err
	}
	for _, i := range ifs {
		if i.Name == name || fmt.Sprint(i.Index) == name {
			return i, nil
		}
	}
	return Interface{}, fmt.Errorf("no interface called %q", name)
}

// LiveAvailable says whether live capture can work here, and if not, what to
// do about it.
func LiveAvailable() (bool, string) { return liveAvailable() }

// OpenLive starts live capture of multicast on ifc.
func OpenLive(ifc Interface) (Source, error) { return openLive(ifc, filterMulticast) }

// liveFilter is what a capture device passes up from the kernel.
type liveFilter int

const (
	// filterMulticast: frames to a group MAC address, the interface in
	// all-multicast or promiscuous mode so every group arrives.
	filterMulticast liveFilter = iota
	// filterGRE: IPv4 GRE, as a switch's ERSPAN mirror arrives, with the
	// interface in its normal state: the mirror is addressed to this host.
	filterGRE
)

// program is the kernel filter for Ethernet frames.
func (f liveFilter) program() []bpf.RawInstruction {
	if f == filterGRE {
		return greOnly
	}
	return multicastOnly
}

func assemble(ins []bpf.Instruction) []bpf.RawInstruction {
	prog, err := bpf.Assemble(ins)
	if err != nil {
		panic(err)
	}
	return prog
}

// multicastOnly passes frames whose destination MAC has the group bit set.
var multicastOnly = assemble([]bpf.Instruction{
	bpf.LoadAbsolute{Off: 0, Size: 1},
	bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 1, SkipTrue: 0, SkipFalse: 1},
	bpf.RetConstant{Val: 1 << 18},
	bpf.RetConstant{Val: 0},
})

// greOnly passes IPv4 GRE (protocol 47), untagged or behind one 802.1Q tag.
var greOnly = assemble([]bpf.Instruction{
	bpf.LoadAbsolute{Off: 12, Size: 2},                                       // 0: EtherType
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8100, SkipTrue: 3},                // 1: tagged: to 5
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 7},               // 2: not IPv4: to 10
	bpf.LoadAbsolute{Off: 23, Size: 1},                                       // 3: IP protocol
	bpf.Jump{Skip: 3},                                                        // 4: to 8
	bpf.LoadAbsolute{Off: 16, Size: 2},                                       // 5: the tagged EtherType
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 3},               // 6: not IPv4: to 10
	bpf.LoadAbsolute{Off: 27, Size: 1},                                       // 7: IP protocol
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(pkt.ProtoGRE), SkipFalse: 1}, // 8: not GRE: to 10
	bpf.RetConstant{Val: 1 << 18},                                            // 9
	bpf.RetConstant{Val: 0},                                                  // 10
})
