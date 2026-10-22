package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Update checking: one question to GitHub at launch, never waited on, silent
// on any failure, cached for a day so a whole site behind one address stays
// well inside GitHub's unauthenticated rate limit. -no-update-check or
// PACKHOUND_NO_UPDATE_CHECK=1 turns it off.
var releasesAPI = "https://api.github.com/repos/andreacoppini/packhound/releases/latest"

const updateCheckTTL = 24 * time.Hour

type updateInfo struct {
	Latest string `json:"latest"`
	URL    string `json:"url"`
}

type cachedCheck struct {
	Checked time.Time  `json:"checked"`
	Info    updateInfo `json:"info"`
}

func checkForUpdate(ctx context.Context, api, current string, allowed bool) (updateInfo, bool) {
	if !allowed || !updateCheckEnabled() {
		return updateInfo{}, false
	}
	if _, ok := parseVersion(current); !ok {
		return updateInfo{}, false // a development build has nothing to compare
	}
	info, ok := cachedResult()
	if !ok {
		var err error
		if info, err = fetchLatest(ctx, api); err != nil {
			return updateInfo{}, false
		}
		storeResult(info)
	}
	if newer(info.Latest, current) {
		return info, true
	}
	return updateInfo{}, false
}

func updateCheckEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("PACKHOUND_NO_UPDATE_CHECK"))) {
	case "", "0", "false", "no":
		return true
	}
	return false
}

func fetchLatest(ctx context.Context, api string) (updateInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	if err != nil {
		return updateInfo{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "packhound/"+version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return updateInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return updateInfo{}, fmt.Errorf("github answered %s", resp.Status)
	}
	var body struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return updateInfo{}, err
	}
	tag := strings.TrimPrefix(strings.TrimSpace(body.TagName), "v")
	if _, ok := parseVersion(tag); !ok {
		return updateInfo{}, fmt.Errorf("unrecognised tag %q", body.TagName)
	}
	return updateInfo{Latest: tag, URL: body.HTMLURL}, nil
}

func newer(latest, current string) bool {
	l, ok1 := parseVersion(latest)
	c, ok2 := parseVersion(current)
	if !ok1 || !ok2 {
		return false
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

func parseVersion(s string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(s), "v"), ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func cachePath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "packhound", "update.json"), nil
}

func cachedResult() (updateInfo, bool) {
	p, err := cachePath()
	if err != nil {
		return updateInfo{}, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return updateInfo{}, false
	}
	var c cachedCheck
	if json.Unmarshal(b, &c) != nil || time.Since(c.Checked) > updateCheckTTL || c.Checked.After(time.Now()) {
		return updateInfo{}, false
	}
	return c.Info, true
}

func storeResult(info updateInfo) {
	p, err := cachePath()
	if err != nil || os.MkdirAll(filepath.Dir(p), 0o755) != nil {
		return
	}
	if b, err := json.Marshal(cachedCheck{Checked: time.Now(), Info: info}); err == nil {
		_ = os.WriteFile(p, b, 0o644)
	}
}

// startUpdateCheck runs the check in the background; the channel is buffered
// so the goroutine finishes even if nobody reads it.
func startUpdateCheck(allowed bool) <-chan updateInfo {
	ch := make(chan updateInfo, 1)
	go func() {
		defer close(ch)
		if info, ok := checkForUpdate(context.Background(), releasesAPI, version, allowed); ok {
			ch <- info
		}
	}()
	return ch
}
