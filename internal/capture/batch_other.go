//go:build !linux

package capture

import "github.com/andreacoppini/packhound/internal/groups"

func kernelTimestamps(uintptr) {}

// startReaders reads each socket with its own goroutine, one datagram at a
// time.
func (j *Joined) startReaders(cs []joined, gs []groups.Group) {
	for i, c := range cs {
		j.conns = append(j.conns, c.conn)
		j.wg.Add(1)
		go func(c joined, g groups.Group) { defer j.wg.Done(); j.readOne(c, g) }(c, gs[i])
	}
}
