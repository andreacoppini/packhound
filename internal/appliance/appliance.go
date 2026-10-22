// Package appliance manages the Linux host when Packhound runs as a virtual
// appliance: network addresses, host name, the admin login, SSH, time, and
// power. It only works on the appliance image, which uses systemd-networkd
// and systemd-resolved; elsewhere Available reports false and nothing here
// is offered.
package appliance

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Marker is written into the appliance image; its presence is what turns
// on host management.
const Marker = "/etc/packhound/appliance"

// Root is prefixed to every path, so tests and the image build can work on a
// directory tree instead of the live system.
var Root = "/"

func path(p string) string { return filepath.Join(Root, p) }

// Available reports whether this is the Packhound appliance.
func Available() bool {
	_, err := os.Stat(path(Marker))
	return err == nil
}

// Offline writes the files without touching running services: for setting
// up an image from a chroot, where there is no systemd to tell.
var Offline bool

// run executes a system command, unless Root points away from the live
// system or this is an offline setup.
var run = func(name string, args ...string) error {
	if Root != "/" || Offline {
		return nil
	}
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ---- network ----

// Iface modes.
const (
	ModeOff     = "off"     // not configured: left down
	ModeCapture = "capture" // up with no address, for listening only
	ModeDHCP    = "dhcp"
	ModeStatic  = "static"
)

// IfaceConfig is how one network interface is set up.
type IfaceConfig struct {
	Name    string   `json:"name"`
	Mode    string   `json:"mode"`
	Address string   `json:"address,omitempty"` // static: 10.0.0.5/24
	Gateway string   `json:"gateway,omitempty"`
	DNS     []string `json:"dns,omitempty"`
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

// Validate checks a configuration before anything is written.
func (c IfaceConfig) Validate() error {
	if !safeName.MatchString(c.Name) {
		return fmt.Errorf("bad interface name %q", c.Name)
	}
	switch c.Mode {
	case ModeOff, ModeCapture, ModeDHCP:
		return nil
	case ModeStatic:
	default:
		return fmt.Errorf("unknown mode %q", c.Mode)
	}
	p, err := netip.ParsePrefix(c.Address)
	if err != nil || !p.Addr().Is4() || p.Bits() < 1 || p.Bits() > 32 {
		return fmt.Errorf("address must be IPv4 with a prefix length, as 10.0.0.5/24 (got %q)", c.Address)
	}
	if p.Addr() == p.Masked().Addr() && p.Bits() < 31 {
		return fmt.Errorf("%s is the network address, not a host address", p.Addr())
	}
	if c.Gateway != "" {
		g, err := netip.ParseAddr(c.Gateway)
		if err != nil || !g.Is4() {
			return fmt.Errorf("bad gateway %q", c.Gateway)
		}
		if !p.Masked().Contains(g) {
			return fmt.Errorf("gateway %s is not in %s", g, p.Masked())
		}
	}
	for _, d := range c.DNS {
		if _, err := netip.ParseAddr(d); err != nil {
			return fmt.Errorf("bad DNS server %q", d)
		}
	}
	return nil
}

func networkFile(name string) string {
	return path("/etc/systemd/network/10-packhound-" + name + ".network")
}

// render writes the systemd-networkd file for an interface.
func (c IfaceConfig) render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Written by Packhound; change it in the web console or with `packhound setup`.\n[Match]\nName=%s\n\n", c.Name)
	switch c.Mode {
	case ModeOff:
		b.WriteString("[Link]\nActivationPolicy=down\nUnmanaged=no\n")
		return b.String()
	case ModeCapture:
		// Up, but with no address of its own: a port for listening.
		b.WriteString("[Link]\nActivationPolicy=up\nRequiredForOnline=no\n\n[Network]\nDHCP=no\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n")
		return b.String()
	}
	b.WriteString("[Network]\n")
	if c.Mode == ModeDHCP {
		b.WriteString("DHCP=ipv4\n")
	} else {
		fmt.Fprintf(&b, "Address=%s\n", c.Address)
		if c.Gateway != "" {
			fmt.Fprintf(&b, "Gateway=%s\n", c.Gateway)
		}
	}
	for _, d := range c.DNS {
		fmt.Fprintf(&b, "DNS=%s\n", d)
	}
	b.WriteString("IPv6AcceptRA=yes\nLinkLocalAddressing=ipv6\n")
	if c.Mode == ModeDHCP {
		b.WriteString("\n[DHCPv4]\nUseHostname=no\n")
	}
	return b.String()
}

// ReadIfaces returns the configuration of every interface that has one.
func ReadIfaces() (map[string]IfaceConfig, error) {
	files, err := filepath.Glob(path("/etc/systemd/network/10-packhound-*.network"))
	if err != nil {
		return nil, err
	}
	out := map[string]IfaceConfig{}
	for _, f := range files {
		c, err := parseNetworkFile(f)
		if err == nil && c.Name != "" {
			out[c.Name] = c
		}
	}
	return out, nil
}

func parseNetworkFile(file string) (IfaceConfig, error) {
	f, err := os.Open(file)
	if err != nil {
		return IfaceConfig{}, err
	}
	defer f.Close()
	c := IfaceConfig{Mode: ModeStatic}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch k {
		case "Name":
			c.Name = v
		case "DHCP":
			if v == "ipv4" || v == "yes" {
				c.Mode = ModeDHCP
			} else if v == "no" {
				c.Mode = ModeCapture
			}
		case "ActivationPolicy":
			if v == "down" {
				c.Mode = ModeOff
			}
		case "Address":
			c.Address, c.Mode = v, ModeStatic
		case "Gateway":
			c.Gateway = v
		case "DNS":
			c.DNS = append(c.DNS, v)
		}
	}
	return c, sc.Err()
}

// WriteIface saves an interface's configuration and applies it.
func WriteIface(c IfaceConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(path("/etc/systemd/network"), 0o755); err != nil {
		return err
	}
	if err := writeFile(networkFile(c.Name), c.render(), 0o644); err != nil {
		return err
	}
	if err := run("networkctl", "reload"); err != nil {
		return err
	}
	if c.Mode == ModeOff {
		return run("ip", "link", "set", c.Name, "down")
	}
	_ = run("ip", "link", "set", c.Name, "up")
	return run("networkctl", "reconfigure", c.Name)
}

// IfaceState is what an interface is doing right now.
type IfaceState struct {
	Name    string   `json:"name"`
	MAC     string   `json:"mac"`
	Up      bool     `json:"up"`
	Carrier bool     `json:"carrier"`
	Addrs   []string `json:"addrs"`
	Speed   string   `json:"speed,omitempty"`
}

// Ifaces lists the physical interfaces with their live state.
func Ifaces() ([]IfaceState, error) {
	nis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []IfaceState
	for _, ni := range nis {
		if ni.Flags&net.FlagLoopback != 0 {
			continue
		}
		st := IfaceState{Name: ni.Name, MAC: ni.HardwareAddr.String(), Up: ni.Flags&net.FlagUp != 0}
		if b, err := os.ReadFile(path("/sys/class/net/" + ni.Name + "/carrier")); err == nil {
			st.Carrier = strings.TrimSpace(string(b)) == "1"
		}
		if b, err := os.ReadFile(path("/sys/class/net/" + ni.Name + "/speed")); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" && s != "-1" {
				st.Speed = s + " Mb/s"
			}
		}
		addrs, _ := ni.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLinkLocalUnicast() {
				st.Addrs = append(st.Addrs, n.String())
			}
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ---- host name ----

var hostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func Hostname() string {
	b, err := os.ReadFile(path("/etc/hostname"))
	if err != nil {
		h, _ := os.Hostname()
		return h
	}
	return strings.TrimSpace(string(b))
}

// ValidHostname checks a host name before anything is written.
func ValidHostname(h string) error {
	if !hostRe.MatchString(h) {
		return fmt.Errorf("a host name is letters, digits and hyphens, up to 63 (got %q)", h)
	}
	return nil
}

func SetHostname(h string) error {
	if err := ValidHostname(h); err != nil {
		return err
	}
	if err := writeFile(path("/etc/hostname"), h+"\n", 0o644); err != nil {
		return err
	}
	// Keep the name resolvable locally, or sudo complains on every use.
	hosts := "127.0.0.1\tlocalhost\n127.0.1.1\t" + h + "\n::1\tlocalhost ip6-localhost ip6-loopback\nff02::1\tip6-allnodes\nff02::2\tip6-allrouters\n"
	if err := writeFile(path("/etc/hosts"), hosts, 0o644); err != nil {
		return err
	}
	return run("hostname", h)
}

// ---- the admin login ----

var userRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ValidUser checks a login name is acceptable to Linux.
func ValidUser(u string) error {
	if !userRe.MatchString(u) || u == "root" {
		return fmt.Errorf("a login name is lower-case letters, digits, - and _, starting with a letter, and not root (got %q)", u)
	}
	return nil
}

// SetOSUser creates the console and SSH login (with sudo) if needed and sets
// its password.
func SetOSUser(user, password string) error {
	if err := ValidUser(user); err != nil {
		return err
	}
	if strings.ContainsAny(password, "\n\r:") {
		return errors.New("the password cannot contain a colon or a line break")
	}
	if Root != "/" {
		return nil
	}
	if _, err := exec.Command("id", user).Output(); err != nil {
		if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "-G", "sudo", user).CombinedOutput(); err != nil {
			return fmt.Errorf("useradd: %v: %s", err, out)
		}
	}
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(user + ":" + password + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chpasswd: %v: %s", err, out)
	}
	return nil
}

// ---- SSH, time, power ----

func SSHEnabled() bool {
	if Root != "/" {
		return false
	}
	return exec.Command("systemctl", "is-enabled", "--quiet", "ssh").Run() == nil
}

func SetSSH(on bool) error {
	if on {
		return run("systemctl", "enable", "--now", "ssh")
	}
	return run("systemctl", "disable", "--now", "ssh")
}

// NTP returns the configured time servers (empty: Debian's pool).
func NTP() []string {
	b, err := os.ReadFile(path("/etc/systemd/timesyncd.conf.d/packhound.conf"))
	if err != nil {
		return nil
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "NTP="); ok {
			return strings.Fields(v)
		}
	}
	return nil
}

var ntpRe = regexp.MustCompile(`^[A-Za-z0-9.:-]{1,253}$`)

func SetNTP(servers []string) error {
	for _, s := range servers {
		if !ntpRe.MatchString(s) {
			return fmt.Errorf("bad time server %q", s)
		}
	}
	if err := os.MkdirAll(path("/etc/systemd/timesyncd.conf.d"), 0o755); err != nil {
		return err
	}
	conf := "[Time]\nNTP=" + strings.Join(servers, " ") + "\n"
	if err := writeFile(path("/etc/systemd/timesyncd.conf.d/packhound.conf"), conf, 0o644); err != nil {
		return err
	}
	return run("systemctl", "restart", "systemd-timesyncd")
}

func Timezone() string {
	if l, err := os.Readlink(path("/etc/localtime")); err == nil {
		if _, tz, ok := strings.Cut(l, "zoneinfo/"); ok {
			return tz
		}
	}
	return "UTC"
}

var tzRe = regexp.MustCompile(`^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+){0,2}$`)

func SetTimezone(tz string) error {
	if !tzRe.MatchString(tz) {
		return fmt.Errorf("bad time zone %q", tz)
	}
	if _, err := os.Stat(path("/usr/share/zoneinfo/" + tz)); err != nil {
		return fmt.Errorf("unknown time zone %q", tz)
	}
	return run("timedatectl", "set-timezone", tz)
}

func Reboot() error   { return run("systemctl", "reboot") }
func Shutdown() error { return run("systemctl", "poweroff") }

// writeFile replaces a file atomically.
func writeFile(name, content string, mode os.FileMode) error {
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil {
		return err
	}
	return os.Rename(tmp, name)
}
