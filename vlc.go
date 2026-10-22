package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Opening a stream in VLC. The page cannot do it itself: browsers will not
// follow a udp:// link, so the console starts VLC on this machine with the
// stream's URL. The URL always comes from a stream the monitor has seen,
// never from the request, so nothing but a multicast address and port ever
// reaches the command line.

var errNoVLC = errors.New("VLC was not found on this computer: install it from https://www.videolan.org, or use the playlist file instead")

// findVLC locates the VLC executable.
func findVLC() (string, error) {
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		candidates = append(candidates, windowsVLC()...)
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"} {
			if d := os.Getenv(env); d != "" {
				candidates = append(candidates, filepath.Join(d, "VideoLAN", "VLC", "vlc.exe"))
			}
		}
	case "darwin":
		candidates = append(candidates, "/Applications/VLC.app/Contents/MacOS/VLC")
		if home, err := os.UserHomeDir(); err == nil {
			candidates = append(candidates, filepath.Join(home, "Applications", "VLC.app", "Contents", "MacOS", "VLC"))
		}
	default:
		candidates = append(candidates, "/usr/bin/vlc", "/usr/local/bin/vlc", "/snap/bin/vlc")
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	if p, err := exec.LookPath("vlc"); err == nil {
		return p, nil
	}
	return "", errNoVLC
}

// streamURL finds the play URL of a stream the monitor knows.
func (c *console) streamURL(key string) (url, name string, err error) {
	for _, r := range c.eng.mon.Snapshot("", 60).Rows {
		if r.Key != key {
			continue
		}
		if r.PlayURL == "" {
			return "", "", fmt.Errorf("%s is not a stream VLC can play (only MPEG-TS over UDP or RTP is)", r.Group)
		}
		name = r.Name
		if name == "" {
			name = r.Group
		}
		return r.PlayURL, name, nil
	}
	return "", "", errors.New("that stream is no longer in the table")
}

func (c *console) handleVLC(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key string `json:"key"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if c.svc != nil {
		writeErr(w, errors.New("VLC cannot open on the server itself: use Playlist .m3u or Copy URL on your own computer"))
		return
	}
	url, name, err := c.streamURL(req.Key)
	if err != nil {
		writeErr(w, err)
		return
	}
	vlc, err := findVLC()
	if err != nil {
		writeErr(w, err)
		return
	}
	// The title VLC shows in its window and playlist: the channel name.
	args := []string{url, "--meta-title=" + name}
	if runtime.GOOS == "windows" {
		args = append(args, "--no-qt-privacy-ask") // no first-run dialog in the way
	}
	cmd := exec.Command(vlc, args...)
	if err := cmd.Start(); err != nil {
		writeErr(w, fmt.Errorf("could not start VLC: %w", err))
		return
	}
	go cmd.Wait() // reap it when the user closes VLC
	c.eng.mon.Logf("Opened %s (%s) in VLC", url, name)
	writeJSON(w, map[string]string{"url": url, "vlc": vlc})
}

// handlePlaylist returns a one-line .m3u playlist for the stream, which any
// player opens, on this machine or another one on the same network.
func (c *console) handlePlaylist(w http.ResponseWriter, r *http.Request) {
	url, name, err := c.streamURL(r.URL.Query().Get("key"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	file := strings.Map(func(r rune) rune {
		if strings.ContainsRune(`<>:"/\|?*`, r) || r < 32 {
			return '_'
		}
		return r
	}, name)
	w.Header().Set("Content-Type", "audio/x-mpegurl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", file+".m3u"))
	fmt.Fprintf(w, "#EXTM3U\n# Saved by Packhound %s on %s\n#EXTINF:-1,%s\n%s\n",
		version, time.Now().Format("2006-01-02 15:04"), strings.ReplaceAll(name, "\n", " "), url)
}
