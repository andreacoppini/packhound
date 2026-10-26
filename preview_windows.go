package main

import "golang.org/x/sys/windows"

// lowerPriority runs an encoder below Packhound itself, so capture and
// analysis come first when the machine is busy.
func lowerPriority(pid int) {
	h, err := windows.OpenProcess(windows.PROCESS_SET_INFORMATION, false, uint32(pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	windows.SetPriorityClass(h, windows.BELOW_NORMAL_PRIORITY_CLASS)
}
