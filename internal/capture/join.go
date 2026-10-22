package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/andreacoppini/packhound/internal/groups"
	"github.com/andreacoppini/packhound/internal/pkt"
)

// Joined is a source that joins groups with ordinary UDP sockets, one socket
// per group, so each socket receives exactly its own group on every platform
// (Linux, macOS and Windows all filter delivery by per-socket membership when
// the socket is bound to the group or joined only to it).
//
// Datagrams travel to the monitor in batches. On Linux each socket is read a
// batch at a time, about ten times a second, with the kernel's own arrival
// time on every datagram: per-datagram wake-ups across a whole IPTV line-up
// cost far more than the analysis itself.
type Joined struct {
	conns  []net.PacketConn
	ch     chan *Batch
	pool   sync.Pool
	cur    *Batch
	pos    int
	closed chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
	Failed []string // groups that could not be joined, and why

	dropped    atomic.Uint64
	readErrors atomic.Uint64
	polled     int // sockets read and closed by the Linux poller
}

// Batch is a run of datagrams from one socket. Payloads point into arena.
type Batch struct {
	Pkts  []pkt.Packet
	arena []byte
}

// Dropped counts datagrams received but thrown away because the monitor
// fell behind.
func (j *Joined) Dropped() uint64 { return j.dropped.Load() }

// OpenJoin joins every group on ifc and reads them. Groups that fail are
// listed in Failed; it is an error only if none could be joined.
func OpenJoin(ifc Interface, gs []groups.Group) (*Joined, error) {
	return openJoin(ifc, gs, true)
}

// OpenHold joins every group on ifc only to hold the joins, for when live
// capture reads the traffic: the sockets are never read, and keep a buffer
// too small to cost anything.
func OpenHold(ifc Interface, gs []groups.Group) (*Joined, error) {
	return openJoin(ifc, gs, false)
}

func openJoin(ifc Interface, gs []groups.Group, read bool) (*Joined, error) {
	ni, err := net.InterfaceByIndex(ifc.Index)
	if err != nil {
		return nil, err
	}
	// A full queue of IPTV batches is a few tens of megabytes at most: each
	// batch's arena holds only the datagrams' own bytes.
	j := &Joined{ch: make(chan *Batch, 1024), closed: make(chan struct{})}
	j.pool.New = func() any { return &Batch{} }
	var cs []joined
	var ok []groups.Group
	for _, g := range gs {
		c, err := joinOne(ni, g, read)
		if err != nil {
			j.Failed = append(j.Failed, fmt.Sprintf("%s: %v", g, err))
			continue
		}
		cs, ok = append(cs, c), append(ok, g)
	}
	if read {
		j.startReaders(cs, ok)
	} else {
		for _, c := range cs {
			j.conns = append(j.conns, c.conn)
		}
	}
	if len(cs) == 0 && len(gs) > 0 {
		return nil, fmt.Errorf("could not join any group: %s", j.Failed[0])
	}
	return j, nil
}

// joined is one group's socket, with the wrapper that was told to report
// each datagram's destination: the option lives in the wrapper as well as
// the socket, so reading through a new wrapper would lose it.
type joined struct {
	conn net.PacketConn
	p4   *ipv4.PacketConn
	p6   *ipv6.PacketConn
}

func joinOne(ni *net.Interface, g groups.Group, read bool) (joined, error) {
	lc := net.ListenConfig{Control: func(network, address string, rc syscall.RawConn) error {
		if err := reuseControl(network, address, rc); err != nil {
			return err
		}
		return rc.Control(func(fd uintptr) {
			onlyJoinedGroups(fd, g.Addr.Is6())
			kernelTimestamps(fd)
		})
	}}
	network, bind := "udp4", fmt.Sprintf("0.0.0.0:%d", g.Port)
	if g.Addr.Is6() {
		network, bind = "udp6", fmt.Sprintf("[::]:%d", g.Port)
	}
	// Asking for the group's address keeps the intent plain, though Go binds
	// a multicast listener to the wildcard regardless; onlyJoinedGroups and
	// the destination check in read are what keep groups apart.
	if runtime.GOOS != "windows" {
		if g.Addr.Is4() {
			bind = netip.AddrPortFrom(g.Addr, g.Port).String()
		} else if !g.Addr.IsLinkLocalMulticast() && !g.Addr.IsInterfaceLocalMulticast() {
			bind = netip.AddrPortFrom(g.Addr, g.Port).String()
		}
	}
	c, err := lc.ListenPacket(context.Background(), network, bind)
	if err != nil {
		return joined{}, err
	}
	j := joined{conn: c}
	ga := &net.UDPAddr{IP: g.Addr.AsSlice()}
	if g.Addr.Is4() {
		j.p4 = ipv4.NewPacketConn(c)
		if err := j.p4.JoinGroup(ni, ga); err != nil {
			c.Close()
			return joined{}, err
		}
		_ = j.p4.SetControlMessage(ipv4.FlagDst, true)
	} else {
		j.p6 = ipv6.NewPacketConn(c)
		if err := j.p6.JoinGroup(ni, ga); err != nil {
			c.Close()
			return joined{}, err
		}
		_ = j.p6.SetControlMessage(ipv6.FlagDst, true)
	}
	if read {
		_ = c.(*net.UDPConn).SetReadBuffer(16 << 20)
	} else {
		_ = c.(*net.UDPConn).SetReadBuffer(4096)
	}
	return j, nil
}

// readOne is the portable reader: one datagram per read, stamped on arrival
// here. On Linux the poller reads IPv4 groups instead.
func (j *Joined) readOne(c joined, g groups.Group) {
	rbuf := make([]byte, 65536) // room for any datagram; copied out at its size
	for {
		var n int
		var src net.Addr
		var err error
		dst := g.Addr
		if c.p4 != nil {
			var cm *ipv4.ControlMessage
			n, cm, src, err = c.p4.ReadFrom(rbuf)
			if cm != nil && cm.Dst != nil {
				if a, ok := netip.AddrFromSlice(cm.Dst.To4()); ok && a.IsMulticast() {
					dst = a
				}
			}
		} else {
			var cm *ipv6.ControlMessage
			n, cm, src, err = c.p6.ReadFrom(rbuf)
			if cm != nil && cm.Dst != nil {
				if a, ok := netip.AddrFromSlice(cm.Dst); ok && a.IsMulticast() {
					dst = a
				}
			}
		}
		if err != nil {
			if j.isClosed() || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		// A datagram for another group is someone else's: the socket that
		// joined that group reports it.
		if dst != g.Addr {
			continue
		}
		b := j.pool.Get().(*Batch)
		b.reset()
		b.add(time.Now(), udpSource(src), g, dst, n, rbuf[:n])
		if !j.send(b) {
			return
		}
	}
}

func udpSource(a net.Addr) netip.AddrPort {
	if ua, ok := a.(*net.UDPAddr); ok {
		return ua.AddrPort()
	}
	return netip.AddrPort{}
}

func (b *Batch) reset() {
	b.Pkts = b.Pkts[:0]
	b.arena = b.arena[:0]
}

// add appends one datagram. size is its length on the wire, which can be
// more than len(data) when a read truncated it.
func (b *Batch) add(at time.Time, src netip.AddrPort, g groups.Group, dst netip.Addr, size int, data []byte) {
	over := 28
	if dst.Is6() {
		over = 48
	}
	start := len(b.arena)
	b.arena = append(b.arena, data...)
	b.Pkts = append(b.Pkts, pkt.Packet{
		Time: at, Src: src.Addr().Unmap(), Dst: dst, Proto: pkt.ProtoUDP,
		SrcPort: src.Port(), DstPort: g.Port, IPLen: size + over,
		Payload: b.arena[start:len(b.arena):len(b.arena)],
	})
}

// fixPayloads repoints payloads after the arena grew (append may move it).
func (b *Batch) fixPayloads() {
	off := 0
	for i := range b.Pkts {
		n := len(b.Pkts[i].Payload)
		b.Pkts[i].Payload = b.arena[off : off+n : off+n]
		off += n
	}
}

func (j *Joined) isClosed() bool {
	select {
	case <-j.closed:
		return true
	default:
		return false
	}
}

// send queues a batch for the monitor, or drops it if the monitor is behind.
func (j *Joined) send(b *Batch) bool {
	b.fixPayloads()
	select {
	case j.ch <- b:
		return true
	case <-j.closed:
		return false
	default:
		j.dropped.Add(uint64(len(b.Pkts)))
		j.pool.Put(b)
		return true
	}
}

// NextBatch returns the next batch of datagrams. The batch is valid until
// the next call to NextBatch or Next.
func (j *Joined) NextBatch() ([]pkt.Packet, error) {
	if j.cur != nil {
		j.pool.Put(j.cur)
		j.cur = nil
	}
	select {
	case b := <-j.ch:
		j.cur, j.pos = b, len(b.Pkts)
		return b.Pkts, nil
	case <-j.closed:
		return nil, ErrClosed
	}
}

// Next returns the next datagram from any joined group.
func (j *Joined) Next() (Frame, error) {
	for j.cur == nil || j.pos >= len(j.cur.Pkts) {
		if j.cur != nil {
			j.pool.Put(j.cur)
			j.cur = nil
		}
		select {
		case b := <-j.ch:
			j.cur, j.pos = b, 0
		case <-j.closed:
			return Frame{}, ErrClosed
		}
	}
	p := &j.cur.Pkts[j.pos]
	j.pos++
	return Frame{Pkt: p, Time: p.Time}, nil
}

// Close leaves every group. Sockets the Linux poller reads are closed by
// the poller itself as it stops, within a tenth of a second.
func (j *Joined) Close() error {
	j.once.Do(func() {
		close(j.closed)
		for _, c := range j.conns {
			c.Close()
		}
	})
	return nil
}

// Count is how many groups are joined.
func (j *Joined) Count() int { return len(j.conns) + j.polled }
