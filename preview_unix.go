//go:build !windows

package main

import "syscall"

// lowerPriority runs an encoder below Packhound itself, so capture and
// analysis come first when the machine is busy.
func lowerPriority(pid int) { _ = syscall.Setpriority(syscall.PRIO_PROCESS, pid, 10) }
