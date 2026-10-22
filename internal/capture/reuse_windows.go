package capture

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// reuseControl lets several sockets share a port: one per group, and alongside
// whatever else on the machine already listens there.
func reuseControl(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return serr
}
