package main

import "golang.org/x/sys/windows/registry"

// windowsVLC reads where the VLC installer says it put vlc.exe.
func windowsVLC() []string {
	var out []string
	for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\VideoLAN\VLC`, registry.QUERY_VALUE|view)
		if err != nil {
			continue
		}
		if p, _, err := k.GetStringValue(""); err == nil && p != "" {
			out = append(out, p)
		}
		k.Close()
	}
	return out
}
