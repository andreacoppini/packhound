package capture

import "golang.org/x/sys/unix"

// onlyJoinedGroups stops Linux handing a socket the traffic of every group
// joined anywhere on the machine (IP_MULTICAST_ALL, on by default): Go binds
// a multicast listener to the wildcard address, so without this every socket
// on a port receives every group sent to that port.
func onlyJoinedGroups(fd uintptr, v6 bool) {
	if v6 {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_ALL, 0)
		return
	}
	_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_ALL, 0)
}
