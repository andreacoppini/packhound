package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/andreacoppini/packhound/internal/appliance"
)

// The appliance's own console: `packhound setup` asks the few things needed
// to reach the web console (address, name, login), and `packhound tty` is
// what the VM's screen shows afterwards.

const (
	defaultConfigPath = "/etc/packhound/config.json"
	defaultStateDir   = "/var/lib/packhound"
	setupDone         = "/etc/packhound/setup.done"
)

type setupAnswers struct {
	mgmt     appliance.IfaceConfig
	hostname string
	user     string
	password string
	listenOn string // interface to capture on
}

// ---- line input ----

type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func newPrompter() *prompter { return &prompter{in: bufio.NewReader(os.Stdin), out: os.Stdout} }

func (p *prompter) line() string {
	s, err := p.in.ReadString('\n')
	if err != nil && s == "" {
		// The console went away: nothing sensible left to do.
		os.Exit(1)
	}
	return strings.TrimSpace(s)
}

func (p *prompter) ask(q, def string) string {
	if def != "" {
		fmt.Fprintf(p.out, "%s [%s]: ", q, def)
	} else {
		fmt.Fprintf(p.out, "%s: ", q)
	}
	if v := p.line(); v != "" {
		return v
	}
	return def
}

func (p *prompter) yes(q string, def bool) bool {
	d := "Y/n"
	if !def {
		d = "y/N"
	}
	for {
		fmt.Fprintf(p.out, "%s [%s]: ", q, d)
		switch strings.ToLower(p.line()) {
		case "":
			return def
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
	}
}

func (p *prompter) secret(q string) string {
	fmt.Fprintf(p.out, "%s: ", q)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(p.out)
		if err != nil {
			os.Exit(1)
		}
		return string(b)
	}
	return p.line()
}

func (p *prompter) newPassword() string {
	for {
		a := p.secret(fmt.Sprintf("Password (at least %d characters)", minPassword))
		if len(a) < minPassword || len(a) > 72 {
			fmt.Fprintf(p.out, "  It must be %d to 72 characters.\n", minPassword)
			continue
		}
		if strings.ContainsAny(a, ":\n\r") {
			fmt.Fprintln(p.out, "  It cannot contain a colon.")
			continue
		}
		if p.secret("Again") != a {
			fmt.Fprintln(p.out, "  Those did not match.")
			continue
		}
		return a
	}
}

// ---- the wizard ----

func runSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	iface := fs.String("iface", "", "management interface (non-interactive)")
	dhcp := fs.Bool("dhcp", false, "use DHCP on the management interface")
	addr := fs.String("address", "", "static address with prefix, e.g. 10.0.0.5/24")
	gw := fs.String("gateway", "", "default gateway")
	dns := fs.String("dns", "", "DNS servers, comma separated")
	host := fs.String("hostname", "packhound", "host name")
	user := fs.String("user", "admin", "login name")
	pwFile := fs.String("password-file", "", "read the password from this file (non-interactive)")
	listen := fs.String("listen", "", "interface to capture on (default: the second interface, else the management one)")
	cfgPath := fs.String("config", defaultConfigPath, "service configuration file")
	state := fs.String("state", defaultStateDir, "service state directory")
	noRestart := fs.Bool("no-restart", false, "do not restart the service afterwards")
	offline := fs.Bool("offline", false, "only write the files (for preparing an image from a chroot)")
	fs.Parse(args)
	if *offline {
		appliance.Offline = true
		*noRestart = true
	}

	if !appliance.Available() {
		return errors.New("setup configures the Packhound appliance, and this is not one (no " + appliance.Marker + ")")
	}
	var a setupAnswers
	if *iface != "" {
		// Non-interactive, for automated deployment.
		a = setupAnswers{hostname: *host, user: *user, listenOn: *listen}
		a.mgmt = appliance.IfaceConfig{Name: *iface, Mode: appliance.ModeDHCP}
		if !*dhcp {
			a.mgmt = appliance.IfaceConfig{Name: *iface, Mode: appliance.ModeStatic, Address: *addr, Gateway: *gw}
		}
		for _, d := range strings.Split(*dns, ",") {
			if d = strings.TrimSpace(d); d != "" {
				a.mgmt.DNS = append(a.mgmt.DNS, d)
			}
		}
		b, err := os.ReadFile(*pwFile)
		if err != nil {
			return fmt.Errorf("-password-file: %w", err)
		}
		a.password = strings.TrimRight(string(b), "\r\n")
		if len(a.password) < minPassword {
			return fmt.Errorf("the password must be at least %d characters", minPassword)
		}
	} else {
		var err error
		if a, err = interview(newPrompter()); err != nil {
			return err
		}
	}
	if err := applySetup(a, *cfgPath, *state); err != nil {
		return err
	}
	if !*noRestart {
		_ = exec.Command("systemctl", "restart", "packhound").Run()
	}
	return nil
}

func interview(p *prompter) (setupAnswers, error) {
	var a setupAnswers
	clear()
	fmt.Println("Packhound appliance setup")
	fmt.Println("=========================")
	fmt.Println()
	fmt.Println("This sets the address of the web console and the login for it.")
	fmt.Println("Everything else is set up in the web console.")
	fmt.Println()

	ifs, err := appliance.Ifaces()
	if err != nil || len(ifs) == 0 {
		return a, errors.New("this machine has no network interfaces")
	}
	fmt.Println("Network interfaces:")
	def := ""
	for i, f := range ifs {
		link := "no link"
		if f.Carrier {
			link = "link up"
			if def == "" {
				def = f.Name
			}
		}
		fmt.Printf("  %d) %-8s %s  %s %s\n", i+1, f.Name, f.MAC, link, f.Speed)
	}
	if def == "" {
		def = ifs[0].Name
	}
	pick := func(q, def string) string {
		for {
			v := p.ask(q, def)
			for i, f := range ifs {
				if v == f.Name || v == fmt.Sprint(i+1) {
					return f.Name
				}
			}
			fmt.Println("  Type a name or number from the list.")
		}
	}
	fmt.Println()
	a.mgmt.Name = pick("Interface for the web console (management)", def)
	if len(ifs) > 1 {
		other := ""
		for _, f := range ifs {
			if f.Name != a.mgmt.Name {
				other = f.Name
				break
			}
		}
		fmt.Println()
		fmt.Println("Packhound can listen on a separate interface (a mirror port, or the")
		fmt.Println("IPTV VLAN) or on the management one. It can be changed later.")
		a.listenOn = pick("Interface to monitor", other)
	} else {
		a.listenOn = a.mgmt.Name
	}

	fmt.Println()
	if p.yes("Get the management address by DHCP?", true) {
		a.mgmt.Mode = appliance.ModeDHCP
	} else {
		a.mgmt.Mode = appliance.ModeStatic
		for {
			a.mgmt.Address = p.ask("Address with prefix length, e.g. 192.168.1.50/24", "")
			a.mgmt.Gateway = p.ask("Default gateway (blank for none)", "")
			a.mgmt.DNS = nil
			for _, d := range strings.FieldsFunc(p.ask("DNS servers, separated by spaces", a.mgmt.Gateway), func(r rune) bool { return r == ' ' || r == ',' }) {
				a.mgmt.DNS = append(a.mgmt.DNS, d)
			}
			if err := a.mgmt.Validate(); err != nil {
				fmt.Println("  " + err.Error())
				continue
			}
			break
		}
	}

	fmt.Println()
	for {
		a.hostname = p.ask("Host name", "packhound")
		if err := appliance.ValidHostname(a.hostname); err != nil {
			fmt.Println("  " + err.Error())
			continue
		}
		break
	}
	fmt.Println()
	fmt.Println("The login opens the web console, and this console and SSH.")
	for {
		a.user = p.ask("Login name", "admin")
		if err := appliance.ValidUser(a.user); err != nil {
			fmt.Println("  " + err.Error())
			continue
		}
		break
	}
	a.password = p.newPassword()

	fmt.Println()
	fmt.Println("Summary")
	fmt.Printf("  Management:  %s, %s\n", a.mgmt.Name, describeIface(a.mgmt))
	fmt.Printf("  Monitoring:  %s\n", a.listenOn)
	fmt.Printf("  Host name:   %s\n", a.hostname)
	fmt.Printf("  Login:       %s\n", a.user)
	fmt.Println()
	if !p.yes("Apply this?", true) {
		return interview(p)
	}
	return a, nil
}

func describeIface(c appliance.IfaceConfig) string {
	switch c.Mode {
	case appliance.ModeDHCP:
		return "DHCP"
	case appliance.ModeStatic:
		s := c.Address
		if c.Gateway != "" {
			s += " via " + c.Gateway
		}
		if len(c.DNS) > 0 {
			s += ", DNS " + strings.Join(c.DNS, " ")
		}
		return s
	case appliance.ModeCapture:
		return "monitoring only, no address"
	}
	return "off"
}

func applySetup(a setupAnswers, cfgPath, state string) error {
	if err := a.mgmt.Validate(); err != nil {
		return err
	}
	fmt.Println("Applying...")
	if err := appliance.WriteIface(a.mgmt); err != nil {
		return fmt.Errorf("network: %w", err)
	}
	// Every other interface comes up without an address, ready to listen on.
	// Offline, the interfaces here are the build machine's, so only the one
	// named for monitoring is set up.
	have, _ := appliance.ReadIfaces()
	var others []string
	if appliance.Offline {
		others = []string{a.listenOn}
	} else {
		ifs, _ := appliance.Ifaces()
		for _, f := range ifs {
			others = append(others, f.Name)
		}
	}
	for _, name := range others {
		if _, ok := have[name]; ok || name == "" || name == a.mgmt.Name {
			continue
		}
		_ = appliance.WriteIface(appliance.IfaceConfig{Name: name, Mode: appliance.ModeCapture})
	}
	if err := appliance.SetHostname(a.hostname); err != nil {
		return err
	}
	if err := appliance.SetOSUser(a.user, a.password); err != nil {
		return err
	}
	store, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	err = store.update(func(c *serverConfig) error {
		c.Users = nil
		if err := setUserPassword(c, a.user, a.password); err != nil {
			return err
		}
		if a.listenOn != "" {
			c.Listen.Iface = a.listenOn
			if c.Listen.Mode == "" {
				c.Listen.Mode = modeCapture
			}
			c.Running = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	// The certificate names the host and its addresses: make a new one.
	os.Remove(filepath.Join(state, "tls.crt"))
	os.Remove(filepath.Join(state, "tls.key"))
	if err := os.WriteFile(setupDone, []byte(time.Now().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Println("Done.")
	return nil
}

// ---- the console screen ----

func clear() { fmt.Print("\033[H\033[2J") }

func runTTY(args []string) error {
	fs := flag.NewFlagSet("tty", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath, "service configuration file")
	state := fs.String("state", defaultStateDir, "service state directory")
	api := fs.String("api", "https://127.0.0.1:443", "the local service")
	fs.Parse(args)

	p := newPrompter()
	if _, err := os.Stat(setupDone); err != nil {
		a, err := interview(p)
		if err != nil {
			fmt.Println(err)
			time.Sleep(5 * time.Second)
			return err
		}
		if err := applySetup(a, *cfgPath, *state); err != nil {
			fmt.Println("Setup failed:", err)
			fmt.Println("Press Enter to start again.")
			p.line()
			return err
		}
		_ = exec.Command("systemctl", "restart", "packhound").Run()
		fmt.Println("Waiting for the network and the service...")
		waitForAddress(a.mgmt.Name, 30*time.Second)
		if store, err := loadConfig(*cfgPath); err == nil {
			tok := store.get().API.Token
			for i := 0; i < 30; i++ {
				if _, err := localSummary(*api, tok); err == nil {
					break
				}
				time.Sleep(time.Second)
			}
		}
	}

	for {
		status(*cfgPath, *api)
		fmt.Println()
		fmt.Println("  1) Network settings    2) Change password    3) Log in to a shell")
		fmt.Println("  4) Reboot              5) Shut down          6) Reset to factory settings")
		fmt.Print("\nChoose, or press Enter to refresh: ")
		if choice := p.line(); choice != "" {
			menu(choice, p, *cfgPath, *state)
		}
	}
}

func menu(choice string, p *prompter, cfgPath, state string) {
	read := func(prompt string) string {
		fmt.Print(prompt)
		return p.line()
	}
	store, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Println(err)
		return
	}
	cfg := store.get()
	user := ""
	if len(cfg.Users) > 0 {
		user = cfg.Users[0].Name
	}
	// Anyone can walk up to a VM console; every action needs the password.
	confirm := func() bool {
		if !checkPassword(cfg, user, p.secret("Password for "+user)) {
			fmt.Println("Wrong password.")
			time.Sleep(2 * time.Second)
			return false
		}
		return true
	}
	switch choice {
	case "1":
		if !confirm() {
			return
		}
		ifs, _ := appliance.Ifaces()
		have, _ := appliance.ReadIfaces()
		fmt.Println()
		for _, f := range ifs {
			c, ok := have[f.Name]
			d := "not configured"
			if ok {
				d = describeIface(c)
			}
			fmt.Printf("  %-8s %s  (now: %s)\n", f.Name, d, strings.Join(f.Addrs, " "))
		}
		name := read("\nInterface to change (Enter to cancel): ")
		if name == "" {
			return
		}
		c := appliance.IfaceConfig{Name: name}
		switch read("  d) DHCP  s) static  m) monitoring only, no address  o) off: ") {
		case "d":
			c.Mode = appliance.ModeDHCP
		case "s":
			c.Mode = appliance.ModeStatic
			c.Address = read("  Address with prefix, e.g. 192.168.1.50/24: ")
			c.Gateway = read("  Gateway (blank for none): ")
			c.DNS = strings.Fields(strings.ReplaceAll(read("  DNS servers: "), ",", " "))
		case "m":
			c.Mode = appliance.ModeCapture
		case "o":
			c.Mode = appliance.ModeOff
		default:
			return
		}
		if err := appliance.WriteIface(c); err != nil {
			fmt.Println("Not changed:", err)
		} else {
			fmt.Println("Applied.")
			waitForAddress(c.Name, 15*time.Second)
		}
		time.Sleep(2 * time.Second)
	case "2":
		if !confirm() {
			return
		}
		pw := p.newPassword()
		err := store.update(func(c *serverConfig) error { return setUserPassword(c, user, pw) })
		if err == nil {
			err = appliance.SetOSUser(user, pw)
		}
		if err != nil {
			fmt.Println("Not changed:", err)
		} else {
			fmt.Println("Changed. It takes effect in the web console straight away.")
		}
		time.Sleep(2 * time.Second)
	case "3":
		clear()
		cmd := exec.Command("/bin/login")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		_ = cmd.Run()
	case "4", "5":
		if !confirm() {
			return
		}
		if choice == "4" {
			_ = appliance.Reboot()
		} else {
			_ = appliance.Shutdown()
		}
		time.Sleep(time.Minute)
	case "6":
		if !confirm() {
			return
		}
		if read("This erases every setting, the login and the network setup. Type RESET to go on: ") != "RESET" {
			return
		}
		os.Remove(cfgPath)
		os.Remove(setupDone)
		files, _ := filepath.Glob("/etc/systemd/network/10-packhound-*.network")
		for _, f := range files {
			os.Remove(f)
		}
		os.RemoveAll(state)
		_ = appliance.Reboot()
		time.Sleep(time.Minute)
	}
}

func waitForAddress(name string, d time.Duration) {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		ifs, _ := appliance.Ifaces()
		for _, f := range ifs {
			if f.Name == name && len(f.Addrs) > 0 {
				return
			}
		}
		time.Sleep(time.Second)
	}
}

func status(cfgPath, api string) {
	clear()
	host := appliance.Hostname()
	fmt.Printf("Packhound %s  ·  %s  ·  %s\n", version, host, time.Now().Format("2006-01-02 15:04"))
	fmt.Println(strings.Repeat("─", 72))
	ifs, _ := appliance.Ifaces()
	conf, _ := appliance.ReadIfaces()
	var urls []string
	fmt.Println("Network")
	for _, f := range ifs {
		link := "no link"
		if f.Carrier {
			link = "link up " + f.Speed
		}
		c, ok := conf[f.Name]
		role := "not configured"
		if ok {
			role = describeIface(c)
		}
		// IPv4 only: an IPv6 address would push the table out of line,
		// and the console's address is given below anyway.
		var v4 []string
		for _, a := range f.Addrs {
			if p, err := netip.ParsePrefix(a); err == nil && p.Addr().Is4() {
				v4 = append(v4, a)
				urls = append(urls, "https://"+p.Addr().String()+"/")
			}
		}
		addrs := strings.Join(v4, " ")
		if addrs == "" {
			addrs = "-"
		}
		fmt.Printf("  %-8s %-18s %-16s %s\n", f.Name, addrs, link, role)
	}
	fmt.Println()
	if len(urls) == 0 {
		fmt.Println("Web console: no address yet. Check the cable, or the DHCP server.")
	} else {
		fmt.Println("Web console: " + strings.Join(urls, "  "))
	}

	store, err := loadConfig(cfgPath)
	if err != nil {
		return
	}
	cfg := store.get()
	sum, err := localSummary(api, cfg.API.Token)
	fmt.Println()
	switch {
	case err != nil:
		fmt.Println("Service: starting, or not answering (" + err.Error() + "). Press Enter to look again.")
	case !sum.Listening:
		fmt.Println("Service: running, not listening. Start it from the web console.")
	default:
		fmt.Printf("Listening on %s (%s): %d streams, %d degraded, %d lost, %s\n",
			sum.Interface, sum.Mode, sum.Streams, sum.Degraded, sum.Lost, fmtRate(sum.BitRate))
	}
	if cfg.SNMP.Enabled {
		fmt.Printf("SNMP: UDP %d, community %q\n", cfg.SNMP.Port, cfg.SNMP.Community)
	}
}

func fmtRate(b float64) string {
	switch {
	case b >= 1e9:
		return fmt.Sprintf("%.2f Gb/s", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.2f Mb/s", b/1e6)
	}
	return fmt.Sprintf("%.1f kb/s", b/1e3)
}

func localSummary(api, token string) (summary, error) {
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		// The service's own self-signed certificate, on the loopback.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	req, _ := http.NewRequest(http.MethodGet, api+"/api/v1/summary", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		return summary{}, errors.New("not reachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return summary{}, fmt.Errorf("answered %s", resp.Status)
	}
	var s summary
	return s, json.NewDecoder(resp.Body).Decode(&s)
}

// runPasswd sets a login's password from the command line, for recovery.
func runPasswd(args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath, "service configuration file")
	fs.Parse(args)
	user := "admin"
	if fs.NArg() > 0 {
		user = fs.Arg(0)
	}
	if err := appliance.ValidUser(user); err != nil {
		return err
	}
	pw := newPrompter().newPassword()
	store, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if err := store.update(func(c *serverConfig) error { return setUserPassword(c, user, pw) }); err != nil {
		return err
	}
	if appliance.Available() {
		if err := appliance.SetOSUser(user, pw); err != nil {
			return err
		}
	}
	fmt.Println("Password set for", user)
	return nil
}
