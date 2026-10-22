//go:build !windows

package capture

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reuseControl lets several sockets share a port: one per group, and alongside
// whatever else on the machine already listens there (Bonjour on 5353, say).
func reuseControl(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if serr == nil {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		}
	})
	if err != nil {
		return err
	}
	return serr
}
