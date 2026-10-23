package capture

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreacoppini/packhound/internal/pkt"
)

// Remote mirroring: a switch copies a port's traffic and sends it, wrapped,
// to an address of this machine. ERSPAN (Cisco, Arista, Juniper, Aruba,
// Ruckus ICX) wraps it in GRE, IP protocol 47, which only a raw socket
// receives: that needs root, or an administrator on Windows. TZSP (MikroTik)
// wraps it in UDP to port 37008, which any program may receive.

// Remote protocols.
const (
	RemoteERSPAN = "erspan"
	RemoteTZSP   = "tzsp"
)

// RemoteConfig says what mirrored traffic to accept.
type RemoteConfig struct {
	Proto   string     // RemoteERSPAN or RemoteTZSP
	Listen  netip.Addr // the local address it arrives at; invalid: any
	From    netip.Addr // only from this switch; invalid: any
	Session int        // only this ERSPAN session; -1: any
}

// RemoteStats says whether mirrored traffic is arriving, and from where.
type RemoteStats struct {
	Proto    string    `json:"proto"`
	Listen   string    `json:"listen"`
	Received uint64    `json:"received"` // wrapped packets that arrived
	Frames   uint64    `json:"frames"`   // mirrored frames unwrapped from them
	Ignored  uint64    `json:"ignored"`  // from another switch or session, or unreadable
	From     string    `json:"from,omitempty"`
	Session  int       `json:"session"` // the latest ERSPAN session seen; -1 for none
	Last     time.Time `json:"last,omitzero"`
}

// Remote is a source of mirrored traffic.
type Remote struct {
	cfg  RemoteConfig
	conn net.PacketConn
	buf  []byte

	received, frames, ignored atomic.Uint64
	mu                        sync.Mutex
	from                      netip.Addr
	session                   int
	last                      time.Time
	closed                    atomic.Bool
}

// OpenRemote starts receiving mirrored traffic.
func OpenRemote(cfg RemoteConfig) (*Remote, error) {
	host := ""
	if cfg.Listen.IsValid() {
		host = cfg.Listen.String()
	}
	var conn net.PacketConn
	var err error
	switch cfg.Proto {
	case RemoteERSPAN:
		conn, err = net.ListenPacket("ip4:gre", host)
		if err != nil {
			if isPermission(err) {
				return nil, errors.New("receiving ERSPAN needs root (or an administrator on Windows): GRE only reaches raw sockets")
			}
			return nil, fmt.Errorf("cannot receive ERSPAN: %w", err)
		}
	case RemoteTZSP:
		conn, err = net.ListenPacket("udp4", net.JoinHostPort(host, fmt.Sprint(pkt.TZSPPort)))
		if err != nil {
			return nil, fmt.Errorf("cannot receive TZSP on port %d: %w", pkt.TZSPPort, err)
		}
	default:
		return nil, fmt.Errorf("unknown remote protocol %q", cfg.Proto)
	}
	if uc, ok := conn.(interface{ SetReadBuffer(int) error }); ok {
		uc.SetReadBuffer(16 << 20) // a busy mirror arrives in bursts
	}
	return &Remote{cfg: cfg, conn: conn, buf: make([]byte, 65536), session: -1}, nil
}

func isPermission(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "permitted") || strings.Contains(s, "permission") || strings.Contains(s, "access")
}

// Next returns the next mirrored frame, as Ethernet. Frame.Data is only
// valid until the next call.
func (r *Remote) Next() (Frame, error) {
	for {
		n, addr, err := r.conn.ReadFrom(r.buf)
		if err != nil {
			if r.closed.Load() {
				return Frame{}, ErrClosed
			}
			return Frame{}, err
		}
		now := time.Now()
		r.received.Add(1)
		src := addrOf(addr)
		if r.cfg.From.IsValid() && src != r.cfg.From {
			r.ignored.Add(1)
			continue
		}
		var frame []byte
		session := -1
		ok := false
		if r.cfg.Proto == RemoteERSPAN {
			// Go's raw IPv4 sockets hand over what follows the IP header.
			frame, session, ok = pkt.GRE(r.buf[:n])
		} else {
			frame, ok = pkt.TZSP(r.buf[:n])
		}
		if !ok || (r.cfg.Session >= 0 && session != r.cfg.Session) {
			r.ignored.Add(1)
			continue
		}
		r.frames.Add(1)
		r.mu.Lock()
		r.from, r.session, r.last = src, session, now
		r.mu.Unlock()
		return Frame{Data: frame, Link: pkt.LinkEthernet, Time: now}, nil
	}
}

func addrOf(a net.Addr) netip.Addr {
	switch a := a.(type) {
	case *net.IPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return ip.Unmap()
	case *net.UDPAddr:
		return a.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

// Stats reports what has arrived.
func (r *Remote) Stats() RemoteStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := RemoteStats{Proto: r.cfg.Proto, Received: r.received.Load(), Frames: r.frames.Load(), Ignored: r.ignored.Load(),
		Session: r.session, Last: r.last, Listen: "any address"}
	if r.cfg.Listen.IsValid() {
		s.Listen = r.cfg.Listen.String()
	}
	if r.from.IsValid() {
		s.From = r.from.String()
	}
	return s
}

func (r *Remote) Close() error {
	r.closed.Store(true)
	return r.conn.Close()
}
