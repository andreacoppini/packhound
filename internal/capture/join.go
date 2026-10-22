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
type Joined struct {
	conns  []net.PacketConn
	ch     chan *joinPkt
	pool   sync.Pool
	prev   *joinPkt
	closed chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
	Failed []string // groups that could not be joined, and why

	dropped atomic.Uint64
}

// Dropped counts datagrams received but thrown away because the monitor
// fell behind.
func (j *Joined) Dropped() uint64 { return j.dropped.Load() }

type joinPkt struct {
	p   pkt.Packet
	buf []byte
}

// OpenJoin joins every group on ifc. Groups that fail are listed in Failed;
// it is an error only if none could be joined.
func OpenJoin(ifc Interface, gs []groups.Group) (*Joined, error) {
	ni, err := net.InterfaceByIndex(ifc.Index)
	if err != nil {
		return nil, err
	}
	j := &Joined{ch: make(chan *joinPkt, 8192), closed: make(chan struct{})}
	j.pool.New = func() any { return &joinPkt{buf: make([]byte, 65536)} }
	for _, g := range gs {
		c, err := joinOne(ni, g)
		if err != nil {
			j.Failed = append(j.Failed, fmt.Sprintf("%s: %v", g, err))
			continue
		}
		j.conns = append(j.conns, c.conn)
		j.wg.Add(1)
		go j.read(c, g)
	}
	if len(j.conns) == 0 && len(gs) > 0 {
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

func joinOne(ni *net.Interface, g groups.Group) (joined, error) {
	lc := net.ListenConfig{Control: func(network, address string, rc syscall.RawConn) error {
		if err := reuseControl(network, address, rc); err != nil {
			return err
		}
		return rc.Control(func(fd uintptr) { onlyJoinedGroups(fd, g.Addr.Is6()) })
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
	_ = c.(*net.UDPConn).SetReadBuffer(8 << 20)
	return j, nil
}

func (j *Joined) read(c joined, g groups.Group) {
	defer j.wg.Done()
	p4, p6 := c.p4, c.p6
	for {
		jp := j.pool.Get().(*joinPkt)
		var n int
		var src net.Addr
		var err error
		dst := g.Addr
		if p4 != nil {
			var cm *ipv4.ControlMessage
			n, cm, src, err = p4.ReadFrom(jp.buf)
			if cm != nil && cm.Dst != nil {
				if a, ok := netip.AddrFromSlice(cm.Dst.To4()); ok && a.IsMulticast() {
					dst = a
				}
			}
		} else {
			var cm *ipv6.ControlMessage
			n, cm, src, err = p6.ReadFrom(jp.buf)
			if cm != nil && cm.Dst != nil {
				if a, ok := netip.AddrFromSlice(cm.Dst); ok && a.IsMulticast() {
					dst = a
				}
			}
		}
		// A datagram for another group is someone else's: the socket that
		// joined that group reports it.
		if err == nil && dst != g.Addr {
			j.pool.Put(jp)
			continue
		}
		if err != nil {
			j.pool.Put(jp)
			select {
			case <-j.closed:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		ua, _ := src.(*net.UDPAddr)
		var sa netip.AddrPort
		if ua != nil {
			sa = ua.AddrPort()
		}
		over := 28
		if dst.Is6() {
			over = 48
		}
		jp.p = pkt.Packet{
			Time: time.Now(), Src: sa.Addr().Unmap(), Dst: dst, Proto: pkt.ProtoUDP,
			SrcPort: sa.Port(), DstPort: g.Port, IPLen: n + over, Payload: jp.buf[:n],
		}
		select {
		case j.ch <- jp:
		case <-j.closed:
			return
		default:
			j.pool.Put(jp) // the monitor is behind; drop rather than block the socket
			j.dropped.Add(1)
		}
	}
}

// Next returns the next datagram from any joined group.
func (j *Joined) Next() (Frame, error) {
	if j.prev != nil {
		j.pool.Put(j.prev)
		j.prev = nil
	}
	select {
	case jp := <-j.ch:
		j.prev = jp
		return Frame{Pkt: &jp.p, Time: jp.p.Time}, nil
	case <-j.closed:
		return Frame{}, ErrClosed
	}
}

// Drain discards everything received, for when the sockets are only there to
// hold the joins while live capture does the reading.
func (j *Joined) Drain() {
	go func() {
		for {
			if _, err := j.Next(); err != nil {
				return
			}
		}
	}()
}

// Close leaves every group.
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
func (j *Joined) Count() int { return len(j.conns) }
