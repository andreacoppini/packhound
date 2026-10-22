package main

import (
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andreacoppini/packhound/internal/capture"
	"github.com/andreacoppini/packhound/internal/groups"
	"github.com/andreacoppini/packhound/internal/monitor"
)

//go:embed web
var webAssets embed.FS

// console is the browser UI. It binds to loopback only: what it shows is
// this machine's view of the network, and nothing off the machine should be
// able to start captures or recordings on it.
type console struct {
	eng      *engine
	defaults startRequest
	update   <-chan updateInfo

	mu        sync.Mutex
	newer     *updateInfo
	recorded  map[string]string // recording file name -> path, for download
	checkedUp bool

	// Set when the console is the background service's: changes are saved,
	// and the page is told what else it may offer.
	svc *service
}

func runConsole(opt options) error {
	cfg := monitor.DefaultConfig()
	c := &console{
		eng:      newEngine(cfg),
		defaults: startRequest{Iface: opt.iface, Mode: opt.mode, Groups: opt.groups, Join: opt.joinToo},
		update:   startUpdateCheck(!opt.noUpdate),
		recorded: map[string]string{},
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", opt.port))
	if err != nil {
		return fmt.Errorf("cannot start the console: %w", err)
	}
	addr := ln.Addr().String()
	link := "http://" + addr

	mux := http.NewServeMux()
	if err := c.routes(mux); err != nil {
		return err
	}

	fmt.Printf("Packhound %s\nConsole: %s\n(leave this window open; close it or press Ctrl-C to quit)\n", version, link)
	if ok, why := capture.LiveAvailable(); !ok {
		fmt.Println("Note:", why)
	}
	if opt.start {
		if err := c.eng.start(c.defaults); err != nil {
			fmt.Println("Could not start:", err)
		}
	}
	if !opt.noBrowser {
		openBrowser(link)
	}
	srv := &http.Server{Handler: c.guard(addr, mux), ReadHeaderTimeout: 10 * time.Second}
	return srv.Serve(ln)
}

// routes registers the page and the console's API on mux.
func (c *console) routes(mux *http.ServeMux) error {
	content, err := fs.Sub(webAssets, "web")
	if err != nil {
		return err
	}
	mux.Handle("/", http.FileServer(http.FS(content)))
	mux.HandleFunc("/api/info", c.handleInfo)
	mux.HandleFunc("/api/start", c.handleStart)
	mux.HandleFunc("/api/stop", c.handleStop)
	mux.HandleFunc("/api/clear", c.handleClear)
	mux.HandleFunc("/api/config", c.handleConfig)
	mux.HandleFunc("/api/state", c.handleState)
	mux.HandleFunc("/api/export", c.handleExport)
	mux.HandleFunc("/api/record", c.handleRecord)
	mux.HandleFunc("/api/recording", c.handleRecording)
	mux.HandleFunc("/api/vlc", c.handleVLC)
	mux.HandleFunc("/api/playlist", c.handlePlaylist)
	return nil
}

// guard refuses requests that did not come from the console's own page. The
// listener is loopback-only, but a web page open in the same browser can
// still aim requests at 127.0.0.1, and a DNS-rebinding page can even read the
// answers; checking Host and Origin stops both.
func (c *console) guard(addr string, h http.Handler) http.Handler {
	_, port, _ := net.SplitHostPort(addr)
	okHost := map[string]bool{addr: true, "localhost:" + port: true, "[::1]:" + port: true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !okHost[r.Host] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" {
			u, err := url.Parse(o)
			if err != nil || !okHost[u.Host] {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
		}
		if r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "expected JSON", http.StatusUnsupportedMediaType)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func readJSON(r *http.Request, v any) error {
	if r.Method != http.MethodPost {
		return fmt.Errorf("POST only")
	}
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func (c *console) pollUpdate() *updateInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.checkedUp {
		select {
		case info, ok := <-c.update:
			c.checkedUp = true
			if ok {
				c.newer = &info
			}
		default:
		}
	}
	return c.newer
}

type configJSON struct {
	SilentAfter float64 `json:"silentAfter"` // seconds
	DropPct     float64 `json:"dropPct"`
	ErrPerMin   int     `json:"errPerMin"`
	NewSenders  bool    `json:"newSenders"`
	AvgSeconds  int     `json:"avgSeconds"`
}

func toJSON(c monitor.Config) configJSON {
	return configJSON{c.SilentAfter.Seconds(), c.DropPct, c.ErrPerMin, c.NewSenders, c.AvgSeconds}
}

func (c *console) handleInfo(w http.ResponseWriter, r *http.Request) {
	ifs, err := capture.Interfaces()
	if err != nil {
		writeErr(w, err)
		return
	}
	live, why := capture.LiveAvailable()
	writeJSON(w, map[string]any{
		"version":    version,
		"interfaces": ifs,
		"live":       live,
		"liveWhy":    why,
		"common":     groups.Common,
		"defaults":   c.defaults,
		"config":     toJSON(c.eng.mon.Config()),
		"update":     c.pollUpdate(),
		"recordDir":  recordingDir(),
		"server":     c.svc.info(r),
	})
}

func (c *console) handleStart(w http.ResponseWriter, r *http.Request) {
	var req startRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if err := c.eng.start(req); err != nil {
		writeErr(w, err)
		return
	}
	// The service remembers what it was told to listen to, and resumes it
	// after a restart.
	if err := c.svc.saveListen(req, true); err != nil {
		c.eng.mon.Logf("Could not save the settings: %v", err)
	}
	writeJSON(w, c.eng.status())
}

func (c *console) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, fmt.Errorf("POST only"))
		return
	}
	c.eng.stop()
	c.noteRecording()
	if err := c.svc.saveRunning(false); err != nil {
		c.eng.mon.Logf("Could not save the settings: %v", err)
	}
	writeJSON(w, c.eng.status())
}

func (c *console) handleClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, fmt.Errorf("POST only"))
		return
	}
	c.eng.mon.Reset()
	writeJSON(w, map[string]bool{"ok": true})
}

func (c *console) handleConfig(w http.ResponseWriter, r *http.Request) {
	var j configJSON
	if err := readJSON(r, &j); err != nil {
		writeErr(w, err)
		return
	}
	cfg := monitor.Config{
		SilentAfter: time.Duration(j.SilentAfter * float64(time.Second)),
		DropPct:     j.DropPct, ErrPerMin: j.ErrPerMin, NewSenders: j.NewSenders, AvgSeconds: j.AvgSeconds,
	}
	if cfg.SilentAfter < time.Second {
		cfg.SilentAfter = time.Second
	}
	c.eng.mon.SetConfig(cfg)
	if err := c.svc.saveAlerts(toJSON(c.eng.mon.Config())); err != nil {
		c.eng.mon.Logf("Could not save the settings: %v", err)
	}
	writeJSON(w, toJSON(c.eng.mon.Config()))
}

func (c *console) handleState(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	win, _ := strconv.Atoi(q.Get("win"))
	snap := c.eng.mon.Snapshot(q.Get("sel"), win)
	// The log and alert lists are capped in the monitor; the page only
	// needs the recent end of the log.
	if len(snap.Log) > 300 {
		snap.Log = snap.Log[len(snap.Log)-300:]
	}
	c.noteRecording()
	writeJSON(w, map[string]any{
		"engine": c.eng.status(),
		"snap":   snap,
		"update": c.pollUpdate(),
	})
}

// noteRecording remembers finished recordings so the page can offer them for
// download, and only those: the download handler serves nothing else.
func (c *console) noteRecording() {
	st := c.eng.status()
	if st.Recording == nil {
		return
	}
	c.mu.Lock()
	c.recorded[st.Recording.Name] = st.Recording.Path
	c.mu.Unlock()
}

func (c *console) handleRecord(w http.ResponseWriter, r *http.Request) {
	var req struct {
		On bool `json:"on"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if req.On {
		st, err := c.eng.startRecording()
		if err != nil {
			writeErr(w, err)
			return
		}
		c.noteRecording()
		writeJSON(w, st)
		return
	}
	c.eng.stopRecording()
	c.noteRecording()
	writeJSON(w, c.eng.status())
}

func (c *console) handleRecording(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	c.mu.Lock()
	path, ok := c.recorded[name]
	c.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if st := c.eng.status(); st.Recording != nil && st.Recording.Active && st.Recording.Name == name {
		http.Error(w, "still recording; stop the recording first", http.StatusConflict)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(path)))
	st, _ := f.Stat()
	http.ServeContent(w, r, filepath.Base(path), st.ModTime(), f)
}

func (c *console) handleExport(w http.ResponseWriter, r *http.Request) {
	snap := c.eng.mon.Snapshot("", 60)
	stamp := time.Now().Format("20060102-150405")
	if r.URL.Query().Get("fmt") == "json" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"packhound-%s.json\"", stamp))
		w.Header().Set("Content-Type", "application/json")
		for i := range snap.Rows {
			snap.Rows[i].Spark = nil
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"exported": time.Now(), "rows": snap.Rows, "alerts": snap.Alerts})
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"packhound-%s.csv\"", stamp))
	w.Header().Set("Content-Type", "text/csv")
	_ = writeCSV(w, snap.Rows)
}

func writeCSV(w io.Writer, rows []monitor.Row) error {
	cw := csv.NewWriter(w)
	cw.Write([]string{"Group", "Family", "Protocol", "Port", "Kind", "Type", "Name", "Sender", "Senders",
		"Rate (b/s)", "Packets/s", "Avg size (B)", "Jitter (ms)", "Errors", "Status", "Problem",
		"First seen", "Last seen", "Packets", "Bytes", "VLAN"})
	for _, r := range rows {
		jit := ""
		if r.JitterMs >= 0 {
			jit = fmt.Sprintf("%.2f", r.JitterMs)
		}
		vlan := ""
		if r.VLAN != 0 {
			vlan = fmt.Sprint(r.VLAN)
		}
		cw.Write([]string{
			r.Group, fmt.Sprintf("IPv%d", r.Family), r.Proto, fmt.Sprint(r.Port), string(r.Kind), r.Type, r.Name,
			r.Sender, fmt.Sprint(r.Senders), fmt.Sprintf("%.0f", r.BPS), fmt.Sprintf("%.1f", r.PPS), fmt.Sprint(r.AvgSize),
			jit, r.Errors, string(r.Status), r.Reason,
			r.FirstSeen.Format(time.RFC3339), r.LastSeen.Format(time.RFC3339), fmt.Sprint(r.Packets), fmt.Sprint(r.Bytes), vlan,
		})
	}
	cw.Flush()
	return cw.Error()
}

func openBrowser(link string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", link)
	case "darwin":
		cmd = exec.Command("open", link)
	default:
		cmd = exec.Command("xdg-open", link)
	}
	_ = cmd.Start()
}
