//go:build !linux

package capture

// Elsewhere a socket receives only the groups it joined.
func onlyJoinedGroups(uintptr, bool) {}
