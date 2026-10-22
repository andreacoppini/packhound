package capture

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/andreacoppini/packhound/internal/groups"
)

// On Linux one goroutine reads every joined IPv4 socket: ten times a second
// it drains each with non-blocking recvmmsg, many datagrams per call. A whole
// line-up then costs a few hundred system calls a second, with no wake-up per
// datagram and no goroutine, poller or timer per socket, which together cost
// far more than the analysis itself. The kernel stamps each datagram as it
// arrives, so jitter and the delay factor are measured exactly as before.

const (
	batchSize  = 64
	batchSlot  = 4096 // bytes kept per datagram; longer ones are counted, and cut short
	batchPause = 100 * time.Millisecond
	oobSize    = 128
)

// kernelTimestamps asks for each datagram's arrival time.
func kernelTimestamps(fd uintptr) {
	_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1)
}

// mmsghdr is struct mmsghdr, which x/sys does not define.
type mmsghdr struct {
	hdr unix.Msghdr
	len uint32
}

// polled is one socket the poller reads.
type polled struct {
	conn net.PacketConn
	fd   int
	g    groups.Group
}

func (j *Joined) startReaders(cs []joined, gs []groups.Group) {
	var ps []polled
	for i, c := range cs {
		if c.p4 == nil {
			// IPv6 groups: few, and light; read the portable way.
			j.conns = append(j.conns, c.conn)
			j.wg.Add(1)
			go func(c joined, g groups.Group) { defer j.wg.Done(); j.readOne(c, g) }(c, gs[i])
			continue
		}
		fd := -1
		if sc, err := c.conn.(*net.UDPConn).SyscallConn(); err == nil {
			_ = sc.Control(func(f uintptr) { fd = int(f) })
		}
		if fd < 0 {
			j.conns = append(j.conns, c.conn)
			j.wg.Add(1)
			go func(c joined, g groups.Group) { defer j.wg.Done(); j.readOne(c, g) }(c, gs[i])
			continue
		}
		ps = append(ps, polled{conn: c.conn, fd: fd, g: gs[i]})
	}
	if len(ps) > 0 {
		j.polled = len(ps)
		j.wg.Add(1)
		go j.poll(ps)
	}
}

// poll owns its sockets: it alone reads them, and it closes them when the
// source closes, so a descriptor is never read after it was closed (and
// perhaps reused for something else).
func (j *Joined) poll(ps []polled) {
	defer j.wg.Done()
	defer func() {
		for _, p := range ps {
			p.conn.Close()
		}
	}()

	hdrs := make([]mmsghdr, batchSize)
	iovs := make([]unix.Iovec, batchSize)
	bufs := make([]byte, batchSize*batchSlot)
	oobs := make([]byte, batchSize*oobSize)
	names := make([]unix.RawSockaddrInet4, batchSize)
	for i := range hdrs {
		iovs[i].Base = &bufs[i*batchSlot]
		iovs[i].SetLen(batchSlot)
		hdrs[i].hdr.Iov = &iovs[i]
		hdrs[i].hdr.SetIovlen(1)
		hdrs[i].hdr.Name = (*byte)(unsafe.Pointer(&names[i]))
		hdrs[i].hdr.Control = &oobs[i*oobSize]
	}

	tick := time.NewTicker(batchPause)
	defer tick.Stop()
	for {
		for _, p := range ps {
			for {
				for i := range hdrs {
					hdrs[i].hdr.Namelen = unix.SizeofSockaddrInet4
					hdrs[i].hdr.SetControllen(oobSize)
					hdrs[i].hdr.Flags = 0
					hdrs[i].len = 0
				}
				// MSG_TRUNC reports a datagram's real length even when it is
				// longer than its slot; the socket is non-blocking already.
				r, _, errno := unix.Syscall6(unix.SYS_RECVMMSG, uintptr(p.fd),
					uintptr(unsafe.Pointer(&hdrs[0])), uintptr(len(hdrs)),
					unix.MSG_TRUNC|unix.MSG_DONTWAIT, 0, 0)
				n := int(r)
				if errno != 0 {
					if errno != unix.EAGAIN && !errors.Is(errno, unix.EINTR) {
						j.readErrors.Add(1)
					}
					break
				}
				if n <= 0 {
					break
				}
				b := j.pool.Get().(*Batch)
				b.reset()
				for i := 0; i < n; i++ {
					h := &hdrs[i]
					oob := oobs[i*oobSize : i*oobSize+int(h.hdr.Controllen)]
					at, dst := parseOOB(oob, p.g.Addr)
					if dst != p.g.Addr {
						continue // another group's: its own socket reports it
					}
					size := int(h.len)
					kept := min(size, batchSlot)
					sa := names[i]
					port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:])
					src := netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), port)
					b.add(at, src, p.g, dst, size, bufs[i*batchSlot:i*batchSlot+kept])
				}
				if len(b.Pkts) > 0 {
					if !j.send(b) {
						return
					}
				} else {
					j.pool.Put(b)
				}
				if n < len(hdrs) {
					break // drained
				}
			}
		}
		select {
		case <-j.closed:
			return
		case <-tick.C:
		}
	}
}

// parseOOB reads the arrival time and destination address from a datagram's
// control messages.
func parseOOB(oob []byte, def netip.Addr) (time.Time, netip.Addr) {
	at, dst := time.Time{}, def
	for len(oob) >= unix.SizeofCmsghdr {
		h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		l := int(h.Len)
		if l < unix.SizeofCmsghdr || l > len(oob) {
			break
		}
		data := oob[unix.SizeofCmsghdr:l]
		switch {
		case h.Level == unix.SOL_SOCKET && h.Type == unix.SCM_TIMESTAMPNS && len(data) >= 16:
			sec := int64(binary.NativeEndian.Uint64(data[0:]))
			nsec := int64(binary.NativeEndian.Uint64(data[8:]))
			at = time.Unix(sec, nsec)
		case h.Level == unix.IPPROTO_IP && h.Type == unix.IP_PKTINFO && len(data) >= 12:
			// struct in_pktinfo: ifindex, local address, header destination.
			if a := netip.AddrFrom4([4]byte(data[8:12])); a.IsMulticast() {
				dst = a
			}
		}
		next := (l + unix.SizeofPtr - 1) &^ (unix.SizeofPtr - 1)
		if next > len(oob) {
			break
		}
		oob = oob[next:]
	}
	if at.IsZero() {
		at = time.Now()
	}
	return at, dst
}
