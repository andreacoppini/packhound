package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// macOS: a BPF device, the same mechanism libpcap uses there. The devices are
// root-only unless Wireshark's ChmodBPF helper has opened them up.

func platformNames([]Interface) {}

func liveAvailable() (bool, string) {
	f, err := openBPF()
	if err != nil {
		return false, err.Error()
	}
	f.Close()
	return true, ""
}

func openBPF() (*os.File, error) {
	var lastErr error
	for i := 0; i < 256; i++ {
		f, err := os.OpenFile(fmt.Sprintf("/dev/bpf%d", i), os.O_RDWR, 0)
		if err == nil {
			return f, nil
		}
		if errors.Is(err, os.ErrPermission) {
			return nil, errors.New("live capture needs root: run with sudo, or install Wireshark's ChmodBPF so your account can capture")
		}
		lastErr = err
		if errors.Is(err, os.ErrNotExist) {
			break
		}
	}
	return nil, fmt.Errorf("no free BPF device: %v", lastErr)
}

func ioctl(fd uintptr, req uint, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(req), uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

type bpfDev struct {
	f       *os.File
	fd      uintptr
	link    int
	buf     []byte
	pend    []byte // records not yet handed out
	closed  atomic.Bool
	dropped atomic.Uint64
	statAt  time.Time
}

func openLive(ifc Interface) (Source, error) {
	f, err := openBPF()
	if err != nil {
		return nil, err
	}
	fd := f.Fd()
	fail := func(what string, err error) (Source, error) {
		f.Close()
		return nil, fmt.Errorf("%s: %w", what, err)
	}

	blen := uint32(1 << 20)
	if err := ioctl(fd, unix.BIOCSBLEN, unsafe.Pointer(&blen)); err != nil {
		return fail("setting the BPF buffer size", err)
	}
	var ifr [32]byte
	copy(ifr[:15], ifc.Name)
	if err := ioctl(fd, unix.BIOCSETIF, unsafe.Pointer(&ifr)); err != nil {
		return fail("attaching to "+ifc.Name, err)
	}
	// Not immediate mode: reads then return a buffer of packets at a time
	// (or at the read timeout), which costs far fewer system calls on a busy
	// port. The kernel stamps each packet, so batching changes no timing.
	zero := uint32(0)
	_ = ioctl(fd, unix.BIOCSSEESENT, unsafe.Pointer(&zero)) // only what is received
	// There is no all-multicast switch for BPF; without promiscuous mode the
	// NIC drops groups this host has not joined.
	if err := ioctl(fd, unix.BIOCPROMISC, nil); err != nil {
		return fail("enabling promiscuous mode on "+ifc.Name, err)
	}
	tv := unix.Timeval{Usec: 250000}
	if err := ioctl(fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&tv)); err != nil {
		return fail("setting a read timeout", err)
	}
	var dlt uint32
	if err := ioctl(fd, unix.BIOCGDLT, unsafe.Pointer(&dlt)); err != nil {
		return fail("reading the link type", err)
	}
	if dlt == 1 { // Ethernet: filter in the kernel on the group bit
		prog, err := bpf.Assemble([]bpf.Instruction{
			bpf.LoadAbsolute{Off: 0, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 1, SkipTrue: 0, SkipFalse: 1},
			bpf.RetConstant{Val: 1 << 18},
			bpf.RetConstant{Val: 0},
		})
		if err != nil {
			return fail("building the filter", err)
		}
		ins := make([]unix.BpfInsn, len(prog))
		for i, r := range prog {
			ins[i] = unix.BpfInsn{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
		}
		p := unix.BpfProgram{Len: uint32(len(ins)), Insns: &ins[0]}
		if err := ioctl(fd, unix.BIOCSETF, unsafe.Pointer(&p)); err != nil {
			return fail("setting the filter", err)
		}
	}
	if err := ioctl(fd, unix.BIOCGBLEN, unsafe.Pointer(&blen)); err != nil {
		return fail("reading the buffer size", err)
	}
	return &bpfDev{f: f, fd: fd, link: int(dlt), buf: make([]byte, blen)}, nil
}

// The BPF record header: a 32-bit timeval, captured and original lengths, and
// the header's own length; records are padded to 4 bytes.
const bpfHdrMin = 18

func (b *bpfDev) Next() (Frame, error) {
	for {
		if b.closed.Load() {
			return Frame{}, ErrClosed
		}
		if len(b.pend) >= bpfHdrMin {
			h := b.pend
			sec := binary.LittleEndian.Uint32(h[0:])
			usec := binary.LittleEndian.Uint32(h[4:])
			caplen := int(binary.LittleEndian.Uint32(h[8:]))
			hdrlen := int(binary.LittleEndian.Uint16(h[16:]))
			if hdrlen+caplen > len(h) {
				b.pend = nil
				continue
			}
			data := h[hdrlen : hdrlen+caplen]
			next := (hdrlen + caplen + 3) &^ 3
			if next > len(h) {
				next = len(h)
			}
			b.pend = h[next:]
			return Frame{Data: data, Link: b.link, Time: time.Unix(int64(sec), int64(usec)*1000)}, nil
		}
		if now := time.Now(); now.Sub(b.statAt) >= time.Second {
			b.statAt = now
			var st unix.BpfStat
			if ioctl(b.fd, unix.BIOCGSTATS, unsafe.Pointer(&st)) == nil {
				b.dropped.Store(uint64(st.Drop))
			}
		}
		n, err := syscall.Read(int(b.fd), b.buf)
		if err != nil {
			if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) {
				continue
			}
			if b.closed.Load() {
				return Frame{}, ErrClosed
			}
			return Frame{}, err
		}
		b.pend = b.buf[:n]
	}
}

func (b *bpfDev) Dropped() uint64 { return b.dropped.Load() }

func (b *bpfDev) Close() error {
	if b.closed.Swap(true) {
		return nil
	}
	go func() {
		time.Sleep(500 * time.Millisecond)
		b.f.Close()
	}()
	return nil
}
