package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/andreacoppini/packhound/internal/appliance"
	"github.com/andreacoppini/packhound/internal/snmp"
)

// The service's settings page: SNMP, the API token, logins, and on the
// appliance the host itself.

type settingsView struct {
	API      apiConfig      `json:"api"`
	SNMP     snmpConfig     `json:"snmp"`
	Users    []string       `json:"users"`
	SNMPInfo map[string]any `json:"snmpInfo"`
	System   *systemView    `json:"system,omitempty"`
	Previews int            `json:"previews"` // live previews at once
}

type systemView struct {
	Hostname   string                           `json:"hostname"`
	Interfaces []appliance.IfaceState           `json:"interfaces"`
	Config     map[string]appliance.IfaceConfig `json:"config"`
	SSH        bool                             `json:"ssh"`
	NTP        []string                         `json:"ntp"`
	Timezone   string                           `json:"timezone"`
	Uptime     string                           `json:"uptime"`
}

func (s *service) settingsView() settingsView {
	cfg := s.store.get()
	v := settingsView{API: cfg.API, SNMP: cfg.SNMP, Previews: s.con.previews.limit()}
	for _, u := range cfg.Users {
		v.Users = append(v.Users, u.Name)
	}
	v.SNMPInfo = map[string]any{"running": s.agent != nil}
	if s.agent != nil {
		v.SNMPInfo["requests"] = s.agent.Requests
		v.SNMPInfo["refused"] = s.agent.BadCommunity
	}
	if appliance.Available() {
		ifs, _ := appliance.Ifaces()
		conf, _ := appliance.ReadIfaces()
		v.System = &systemView{
			Hostname: appliance.Hostname(), Interfaces: ifs, Config: conf, SSH: appliance.SSHEnabled(),
			NTP: appliance.NTP(), Timezone: appliance.Timezone(), Uptime: time.Since(s.started).Round(time.Second).String(),
		}
	}
	return v
}

// handleSettings: GET returns the settings; POST changes one section.
func (s *service) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, s.settingsView())
		return
	}
	var req struct {
		Section string `json:"section"`

		SNMP *snmpConfig `json:"snmp"`
		API  *struct {
			Enabled bool `json:"enabled"`
			NewKey  bool `json:"newKey"`
		} `json:"api"`
		Password *struct {
			Current string `json:"current"`
			New     string `json:"new"`
		} `json:"password"`
		Previews int `json:"previews"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	me := s.session(r)
	var err error
	switch req.Section {
	case "snmp":
		if req.SNMP == nil {
			err = errors.New("no SNMP settings")
			break
		}
		n := *req.SNMP
		if n.Enabled && strings.TrimSpace(n.Community) == "" {
			err = errors.New("set a community, or turn SNMP off")
			break
		}
		if _, e := parseAllow(n.Allow); e != nil {
			err = e
			break
		}
		if _, e := snmp.ParseOID(n.BaseOID); e != nil {
			err = fmt.Errorf("base OID: %v", e)
			break
		}
		if n.Port < 1 || n.Port > 65535 {
			err = errors.New("bad SNMP port")
			break
		}
		err = s.store.update(func(c *serverConfig) error { c.SNMP = n; return nil })
		if err == nil {
			err = s.startSNMP()
		}
	case "api":
		if req.API == nil {
			err = errors.New("no API settings")
			break
		}
		err = s.store.update(func(c *serverConfig) error {
			c.API.Enabled = req.API.Enabled
			if req.API.NewKey {
				c.API.Token = newToken()
			}
			return nil
		})
	case "previews":
		if req.Previews < 1 || req.Previews > 16 {
			err = errors.New("allow 1 to 16 previews at once")
			break
		}
		err = s.store.update(func(c *serverConfig) error { c.Preview.Max = req.Previews; return nil })
		if err == nil {
			s.con.previews.setLimit(req.Previews)
		}
	case "password":
		if req.Password == nil || me == nil {
			err = errors.New("no password given")
			break
		}
		if !checkPassword(s.store.get(), me.user, req.Password.Current) {
			time.Sleep(time.Second)
			err = errors.New("the current password is wrong")
			break
		}
		err = s.store.update(func(c *serverConfig) error { return setUserPassword(c, me.user, req.Password.New) })
		// On the appliance the same login opens the console and SSH.
		if err == nil && appliance.Available() {
			if e := appliance.SetOSUser(me.user, req.Password.New); e != nil {
				err = fmt.Errorf("the web password changed, but the console login did not: %v", e)
			}
		}
	default:
		err = fmt.Errorf("unknown section %q", req.Section)
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	s.eng.mon.Logf("Settings changed: %s", req.Section)
	writeJSON(w, s.settingsView())
}

// handleSystem changes the appliance host: network, name, SSH, time, power.
func (s *service) handleSystem(w http.ResponseWriter, r *http.Request) {
	if !appliance.Available() {
		writeErr(w, errors.New("host settings are only available on the Packhound appliance"))
		return
	}
	var req struct {
		Action   string                 `json:"action"`
		Iface    *appliance.IfaceConfig `json:"iface"`
		Hostname string                 `json:"hostname"`
		SSH      bool                   `json:"ssh"`
		NTP      []string               `json:"ntp"`
		Timezone string                 `json:"timezone"`
		Password string                 `json:"password"` // confirms power actions
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	me := s.session(r)
	var err error
	switch req.Action {
	case "iface":
		if req.Iface == nil {
			err = errors.New("no interface settings")
			break
		}
		err = appliance.WriteIface(*req.Iface)
	case "hostname":
		err = appliance.SetHostname(req.Hostname)
	case "ssh":
		err = appliance.SetSSH(req.SSH)
	case "time":
		if req.Timezone != "" {
			err = appliance.SetTimezone(req.Timezone)
		}
		if err == nil {
			err = appliance.SetNTP(req.NTP)
		}
	case "reboot", "shutdown":
		if me == nil || !checkPassword(s.store.get(), me.user, req.Password) {
			time.Sleep(time.Second)
			err = errors.New("enter your password to confirm")
			break
		}
		writeJSON(w, map[string]bool{"ok": true})
		s.eng.mon.Logf("%s requested by %s", req.Action, me.user)
		go func() {
			time.Sleep(time.Second)
			s.eng.stop()
			if req.Action == "reboot" {
				_ = appliance.Reboot()
			} else {
				_ = appliance.Shutdown()
			}
		}()
		return
	default:
		err = fmt.Errorf("unknown action %q", req.Action)
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	s.eng.mon.Logf("System settings changed: %s", req.Action)
	writeJSON(w, s.settingsView())
}
