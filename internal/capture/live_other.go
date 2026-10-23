//go:build !linux && !darwin && !windows

package capture

import "errors"

func platformNames([]Interface) {}

func liveAvailable() (bool, string) {
	return false, "live capture is not supported on this platform; join groups instead"
}

func openLive(Interface, liveFilter) (Source, error) {
	return nil, errors.New("live capture is not supported on this platform")
}
