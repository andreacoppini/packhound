package capture

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/andreacoppini/packhound/internal/pkt"
)

// Linux: an AF_PACKET socket bound to the interface, in all-multicast mode
// (which, unlike promiscuous mode, does not also drown the socket in other
// hosts' unicast), with a kernel filter that passes only group-addressed
// frames.

func platformNames([]Interface) {}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func liveAvailable() (bool, string) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return false, "live capture needs root: run with sudo, or once: sudo setcap cap_net_raw,cap_net_admin+ep ./packhound"
		}
		return false, "live capture is unavailable: " + err.Error()
	}
	unix.Close(fd)
	return true, ""
}

type afPacket struct {
	fd      int
	dropped atomic.Uint64
	statAt  time.Time
	buf     []byte
	oob     []byte
	closed  atomic.Bool
}

func openLive(ifc Interface, filter liveFilter) (Source, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		if ok, why := liveAvailable(); !ok {
			return nil, errors.New(why)
		}
		return nil, err
	}
	fail := func(what string, err error) (Source, error) {
		unix.Close(fd)
		return nil, fmt.Errorf("%s: %w", what, err)
	}

	// The filter goes on before the bind, so nothing unfiltered queues up
	// in between. Loopback frames have no group MAC to filter on; the
	// decoder's IP check does the job there.
	if !ifc.Loopback || filter == filterGRE {
		prog := filter.program()
		ins := make([]unix.SockFilter, len(prog))
		for i, r := range prog {
			ins[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
		}
		fprog := unix.SockFprog{Len: uint16(len(ins)), Filter: &ins[0]}
		if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog); err != nil {
			return fail("attaching the capture filter", err)
		}
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifc.Index}); err != nil {
		return fail("binding to "+ifc.Name, err)
	}
	if filter == filterMulticast {
		mreq := unix.PacketMreq{Ifindex: int32(ifc.Index), Type: unix.PACKET_MR_ALLMULTI}
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
			return fail("enabling all-multicast on "+ifc.Name, err)
		}
	}
	// A big receive buffer rides out the moments the monitor is busy. The
	// forced variant needs CAP_NET_ADMIN; the plain one is capped by
	// net.core.rmem_max.
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 32<<20) != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 32<<20)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1)
	tv := unix.Timeval{Usec: 250000}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fail("setting a read timeout", err)
	}
	return &afPacket{fd: fd, buf: make([]byte, 65536), oob: make([]byte, 128)}, nil
}

func (a *afPacket) Next() (Frame, error) {
	for {
		if a.closed.Load() {
			return Frame{}, ErrClosed
		}
		// The kernel's drop count resets each time it is read, so it is
		// read here, by the one goroutine using the socket, and summed.
		if now := time.Now(); now.Sub(a.statAt) >= time.Second {
			a.statAt = now
			if st, err := unix.GetsockoptTpacketStats(a.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS); err == nil {
				a.dropped.Add(uint64(st.Drops))
			}
		}
		n, oobn, _, from, err := unix.Recvmsg(a.fd, a.buf, a.oob, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			if a.closed.Load() {
				return Frame{}, ErrClosed
			}
			return Frame{}, err
		}
		// What this host sends is not what it receives.
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		return Frame{Data: a.buf[:n], Link: pkt.LinkEthernet, Time: stamp(a.oob[:oobn])}, nil
	}
}

func stamp(oob []byte) time.Time {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err == nil {
		for _, m := range msgs {
			if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_TIMESTAMPNS && len(m.Data) >= int(unsafe.Sizeof(unix.Timespec{})) {
				ts := (*unix.Timespec)(unsafe.Pointer(&m.Data[0]))
				return time.Unix(int64(ts.Sec), int64(ts.Nsec))
			}
		}
	}
	return time.Now()
}

func (a *afPacket) Dropped() uint64 { return a.dropped.Load() }

func (a *afPacket) Close() error {
	if a.closed.Swap(true) {
		return nil
	}
	// The reader notices within its read timeout; closing the descriptor
	// under it would let a new socket reuse the number.
	go func() {
		time.Sleep(500 * time.Millisecond)
		unix.Close(a.fd)
	}()
	return nil
}
