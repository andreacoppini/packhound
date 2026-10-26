package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/andreacoppini/packhound/internal/appliance"
	"github.com/andreacoppini/packhound/internal/monitor"
	"github.com/andreacoppini/packhound/internal/snmp"
)

// The background service: `packhound server`. It listens all the time, with
// the settings it was last given, and offers the console to the network
// behind a login, over HTTPS, with the REST API and an SNMP agent beside it.

type serverOptions struct {
	config   string
	state    string // recordings and the TLS certificate
	https    string // address for the console and API
	http     string // plain HTTP, which only redirects to HTTPS
	snmpAddr string // overrides the configured SNMP port, for testing
}

type service struct {
	opt     serverOptions
	store   *configStore
	eng     *engine
	con     *console
	agent   *snmp.Agent
	started time.Time

	mu       sync.Mutex
	sessions map[string]*session
	failures map[string]*failure // login failures by client address
}

type session struct {
	user    string
	expires time.Time
}

type failure struct {
	count int
	first time.Time
}

const (
	sessionCookie = "packhound_session"
	sessionLife   = 12 * time.Hour
)

func runServer(opt serverOptions) error {
	store, err := loadConfig(opt.config)
	if err != nil {
		return err
	}
	cfg := store.get()
	if len(cfg.Users) == 0 {
		log.Printf("No login is set: run `packhound setup` (or `packhound passwd`) to create one")
	}
	recordDirOverride = filepath.Join(opt.state, "recordings")
	if err := os.MkdirAll(recordDirOverride, 0o700); err != nil {
		return err
	}

	mcfg := monitor.DefaultConfig()
	s := &service{
		opt: opt, store: store, eng: newEngine(mcfg), started: time.Now(),
		sessions: map[string]*session{}, failures: map[string]*failure{},
	}
	s.eng.mon.SetConfig(fromJSON(cfg.Alerts))
	s.con = &console{eng: s.eng, defaults: cfg.Listen, update: startUpdateCheck(false), recorded: map[string]string{}, svc: s}
	// On the appliance, previews share the machine with monitoring: two at
	// once by default.
	maxPreviews := cfg.Preview.Max
	if maxPreviews <= 0 {
		maxPreviews = 2
	}
	s.con.previews = newPreviews(s.eng.mon, findFFmpeg(), filepath.Join(opt.state, "previews"), maxPreviews)

	// Resume listening as last told to.
	if cfg.Running {
		if err := s.eng.start(cfg.Listen); err != nil {
			s.eng.mon.Logf("Could not resume listening: %v", err)
			log.Printf("could not resume listening: %v", err)
		} else {
			log.Printf("listening on %s (%s)", cfg.Listen.Iface, cfg.Listen.Mode)
		}
	}

	if err := s.startSNMP(); err != nil {
		log.Printf("SNMP agent not started: %v", err)
		s.eng.mon.Logf("SNMP agent not started: %v", err)
	}

	cert, err := loadOrMakeCert(opt.state)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	if err := s.con.routes(mux); err != nil {
		return err
	}
	if cfg.Mosaic.Refresh != 0 {
		if err := s.con.mosaic.setRefresh(cfg.Mosaic.Refresh); err != nil {
			log.Printf("mosaic: %v", err)
		}
	}
	s.con.mosaic.save = func(seconds int) error {
		return s.store.update(func(c *serverConfig) error {
			c.Mosaic.Refresh = seconds
			return nil
		})
	}
	mux.HandleFunc("/auth/login", s.handleLogin)
	mux.HandleFunc("/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/v1/", s.handleAPI)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/system", s.handleSystem)

	srv := &http.Server{
		Addr:              opt.https,
		Handler:           s.guard(mux),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	errc := make(chan error, 2)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	if opt.http != "" {
		redirect := &http.Server{Addr: opt.http, ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				host = r.Host
			}
			if _, port, _ := net.SplitHostPort(opt.https); port != "" && port != "443" {
				host = net.JoinHostPort(host, port)
			}
			http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
		})}
		go func() {
			if err := redirect.ListenAndServe(); err != nil {
				log.Printf("HTTP redirect not started: %v", err)
			}
		}()
	}
	log.Printf("Packhound %s service: console on https://%s", version, opt.https)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		return err
	case <-sig:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	s.eng.stop()
	if s.agent != nil {
		s.agent.Close()
	}
	return nil
}

func fromJSON(j configJSON) monitor.Config {
	c := monitor.Config{
		SilentAfter: time.Duration(j.SilentAfter * float64(time.Second)),
		DropPct:     j.DropPct, ErrPerMin: j.ErrPerMin, NewSenders: j.NewSenders, AvgSeconds: j.AvgSeconds,
	}
	if c.SilentAfter < time.Second {
		c.SilentAfter = 5 * time.Second
	}
	if c.AvgSeconds < 1 {
		c.AvgSeconds = 1
	}
	return c
}

// ---- hooks the console calls; all are no-ops on the desktop ----

func (s *service) saveListen(req startRequest, running bool) error {
	if s == nil {
		return nil
	}
	return s.store.update(func(c *serverConfig) error {
		c.Listen, c.Running = req, running
		return nil
	})
}

func (s *service) saveRunning(running bool) error {
	if s == nil {
		return nil
	}
	return s.store.update(func(c *serverConfig) error {
		c.Running = running
		return nil
	})
}

func (s *service) saveAlerts(j configJSON) error {
	if s == nil {
		return nil
	}
	return s.store.update(func(c *serverConfig) error {
		c.Alerts = j
		return nil
	})
}

// info tells the page it is talking to the service, and who is logged in.
func (s *service) info(r *http.Request) any {
	if s == nil {
		return nil
	}
	user := ""
	if se := s.session(r); se != nil {
		user = se.user
	}
	return map[string]any{
		"user":      user,
		"appliance": appliance.Available(),
		"hostname":  s.hostname(),
	}
}

func (s *service) hostname() string {
	if appliance.Available() {
		return appliance.Hostname()
	}
	h, _ := os.Hostname()
	return h
}

// ---- SNMP ----

func (s *service) startSNMP() error {
	cfg := s.store.get().SNMP
	if s.agent != nil {
		s.agent.Close()
		s.agent = nil
	}
	if !cfg.Enabled {
		return nil
	}
	allow, err := parseAllow(cfg.Allow)
	if err != nil {
		return err
	}
	if cfg.Community == "" {
		return errors.New("no community set")
	}
	a := snmp.NewAgent(snmp.Config{Community: cfg.Community, Allow: allow}, s.snmpTree)
	addr := s.opt.snmpAddr
	if addr == "" {
		addr = fmt.Sprintf(":%d", cfg.Port)
	}
	if err := a.Listen(addr); err != nil {
		return err
	}
	s.agent = a
	go a.Serve()
	s.eng.mon.Logf("SNMP agent answering on UDP %s", addr)
	return nil
}

// ---- access ----

// open are the paths that work without logging in: the login page itself
// and what it needs.
var open = map[string]bool{"/login.html": true, "/style.css": true, "/icon.svg": true, "/login.js": true, "/auth/login": true, "/mosaic.js": true, "/watch.js": true, "/hls.min.js": true}

func (s *service) guard(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN") // the mosaic shows the player in a frame
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")

		// Machines (NMS polling) use the API token; the token never opens
		// the console, only the read-only API.
		if strings.HasPrefix(r.URL.Path, "/api/v1/") || r.URL.Path == "/metrics" {
			if s.tokenOK(r) || s.session(r) != nil {
				h.ServeHTTP(w, r)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="packhound"`)
			http.Error(w, "an API token is needed: Authorization: Bearer <token>, or ?token=<token>", http.StatusUnauthorized)
			return
		}
		// The mosaic is read-only, so the API token opens it too: a wall
		// screen can show /mosaic?token=... without logging in.
		if open[r.URL.Path] || (r.URL.Path == "/mosaic" || r.URL.Path == "/watch") && s.tokenOK(r) {
			h.ServeHTTP(w, r)
			return
		}
		if s.session(r) == nil {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, `{"error":"not logged in"}`, http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login.html", http.StatusFound)
			return
		}
		// Changes must come from the console's own page. The session cookie
		// is SameSite=Strict, and a cross-site form cannot send JSON; the
		// Origin check closes what is left.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" {
				if u, err := url.Parse(o); err != nil || u.Host != r.Host {
					http.Error(w, "forbidden origin", http.StatusForbidden)
					return
				}
			}
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") && !isUpload(r) {
				http.Error(w, "expected JSON", http.StatusUnsupportedMediaType)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func (s *service) tokenOK(r *http.Request) bool {
	cfg := s.store.get().API
	if !cfg.Enabled || cfg.Token == "" {
		return false
	}
	got := r.URL.Query().Get("token")
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		got = strings.TrimPrefix(a, "Bearer ")
	}
	if k := r.Header.Get("X-API-Key"); k != "" {
		got = k
	}
	return got != "" && subtleEqual(got, cfg.Token)
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func (s *service) session(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	se := s.sessions[c.Value]
	if se == nil || time.Now().After(se.expires) {
		delete(s.sessions, c.Value)
		return nil
	}
	se.expires = time.Now().Add(sessionLife) // sliding
	return se
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (s *service) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ User, Password string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	ip := clientIP(r)
	s.mu.Lock()
	f := s.failures[ip]
	if f != nil && time.Since(f.first) > 15*time.Minute {
		delete(s.failures, ip)
		f = nil
	}
	locked := f != nil && f.count >= 10
	s.mu.Unlock()
	if locked {
		writeErr(w, errors.New("too many failed logins from this address; wait 15 minutes"))
		return
	}
	if !checkPassword(s.store.get(), req.User, req.Password) {
		s.mu.Lock()
		if s.failures[ip] == nil {
			s.failures[ip] = &failure{first: time.Now()}
		}
		s.failures[ip].count++
		s.mu.Unlock()
		time.Sleep(time.Second)
		log.Printf("failed login for %q from %s", req.User, ip)
		writeErr(w, errors.New("wrong user name or password"))
		return
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	delete(s.failures, ip)
	s.sessions[tok] = &session{user: req.User, expires: time.Now().Add(sessionLife)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	log.Printf("%s logged in from %s", req.User, ip)
	writeJSON(w, map[string]string{"user": req.User})
}

func (s *service) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login.html", http.StatusFound)
}

// ---- TLS ----

// loadOrMakeCert uses dir/tls.crt and tls.key, making a self-signed pair the
// first time. Replace the files with a certificate from your own CA to be
// rid of the browser warning.
func loadOrMakeCert(dir string) (tls.Certificate, error) {
	crt, key := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if c, err := tls.LoadX509KeyPair(crt, key); err == nil {
		return c, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	host, _ := os.Hostname()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"Packhound"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host, "localhost"},
	}
	// Name every address the machine has now, so the warning is the only one.
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				tmpl.IPAddresses = append(tmpl.IPAddresses, n.IP)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pk.PublicKey, pk)
	if err != nil {
		return tls.Certificate{}, err
	}
	kb, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(crt, key)
}
