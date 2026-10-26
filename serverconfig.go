package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/andreacoppini/packhound/internal/monitor"
)

// serverConfig is everything the background service remembers. It lives in
// one JSON file, readable only by root, and is rewritten whole on each change.
type serverConfig struct {
	// What to listen to, and whether to be listening: set from the console,
	// and resumed at every start.
	Listen  startRequest `json:"listen"`
	Running bool         `json:"running"`

	Alerts configJSON `json:"alerts"`

	Users []serverUser `json:"users"`
	API   apiConfig    `json:"api"`
	SNMP  snmpConfig   `json:"snmp"`

	Mosaic  mosaicConfig  `json:"mosaic"`
	Preview previewConfig `json:"preview"`
}

type previewConfig struct {
	Max int `json:"max"` // previews encoding at once; 0: the default
}

type mosaicConfig struct {
	Refresh int `json:"refresh"` // seconds; 0: the default
}

type serverUser struct {
	Name string `json:"name"`
	Hash string `json:"hash"` // bcrypt
}

type apiConfig struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token"`
}

type snmpConfig struct {
	Enabled   bool     `json:"enabled"`
	Port      int      `json:"port"`
	Community string   `json:"community"`
	Allow     []string `json:"allow"` // manager addresses or prefixes; empty: anyone
	BaseOID   string   `json:"baseOID"`
	Location  string   `json:"location"`
	Contact   string   `json:"contact"`
}

// defaultBaseOID sits under net-snmp's playpen arc, which exists for exactly
// this: private MIBs on sites without an enterprise number of their own. A
// site with an IANA enterprise number can move the tree under it.
const defaultBaseOID = "1.3.6.1.4.1.8072.9999.9999.7"

func defaultServerConfig() serverConfig {
	return serverConfig{
		Listen: startRequest{Mode: modeCapture, Join: true},
		Alerts: toJSON(monitor.DefaultConfig()),
		API:    apiConfig{Enabled: true, Token: newToken()},
		SNMP:   snmpConfig{Enabled: true, Port: 161, Community: "public", BaseOID: defaultBaseOID},
	}
}

func newToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// configStore guards the configuration and its file.
//
// More than one process writes it: the service, and `packhound setup`,
// `passwd` and the VM console while the service runs. So each read and
// change first picks up the file if someone else has rewritten it.
type configStore struct {
	path  string
	mu    sync.Mutex
	cfg   serverConfig
	mtime time.Time
}

func loadConfig(path string) (*configStore, error) {
	s := &configStore{path: path, cfg: defaultServerConfig()}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// reload reads the file if it changed since it was last read or written.
func (s *configStore) reload() error {
	st, err := os.Stat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.ModTime().Equal(s.mtime) {
		return nil
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	c := defaultServerConfig()
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("%s: %w", s.path, err)
	}
	s.cfg, s.mtime = c, st.ModTime()
	if s.cfg.SNMP.BaseOID == "" {
		s.cfg.SNMP.BaseOID = defaultBaseOID
	}
	if s.cfg.SNMP.Port == 0 {
		s.cfg.SNMP.Port = 161
	}
	if s.cfg.API.Token == "" {
		s.cfg.API.Token = newToken()
	}
	return nil
}

func (s *configStore) get() serverConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reload(); err != nil {
		log.Printf("configuration not reloaded: %v", err)
	}
	c := s.cfg
	c.Users = append([]serverUser(nil), s.cfg.Users...)
	return c
}

// update changes the configuration and saves it; f returns an error to
// abandon the change.
func (s *configStore) update(f func(*serverConfig) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reload(); err != nil {
		return err
	}
	c := s.cfg
	c.Users = append([]serverUser(nil), s.cfg.Users...)
	if err := f(&c); err != nil {
		return err
	}
	if err := s.write(c); err != nil {
		return err
	}
	s.cfg = c
	return nil
}

func (s *configStore) write(c serverConfig) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	if st, err := os.Stat(s.path); err == nil {
		s.mtime = st.ModTime()
	}
	return nil
}

// ---- users ----

const minPassword = 8

func setUserPassword(c *serverConfig, name, password string) error {
	if len(password) < minPassword {
		return fmt.Errorf("the password must be at least %d characters", minPassword)
	}
	if len(password) > 72 {
		return errors.New("the password must be at most 72 characters")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	for i := range c.Users {
		if c.Users[i].Name == name {
			c.Users[i].Hash = string(h)
			return nil
		}
	}
	c.Users = append(c.Users, serverUser{Name: name, Hash: string(h)})
	return nil
}

// dummyHash is compared against when the user does not exist, so a wrong
// name takes as long to refuse as a wrong password.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("packhound-no-such-user"), bcrypt.DefaultCost)

func checkPassword(c serverConfig, name, password string) bool {
	for _, u := range c.Users {
		if u.Name == name {
			return bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(password)) == nil
		}
	}
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
	return false
}

// ---- SNMP access list ----

func parseAllow(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("bad manager address %q", s)
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("bad manager network %q", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
