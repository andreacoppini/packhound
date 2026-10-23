// Command packhound watches the multicast streams arriving at a network port:
// IPTV, AES67 audio, mDNS, SSDP, PTP, IGMP and the rest, with each stream's
// bit rate, packet rate, senders and health.
//
// Run it with no arguments for the browser console, or headless:
//
//	packhound -i eth0 -duration 30s -out streams.csv
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/andreacoppini/packhound/internal/capture"
	"github.com/andreacoppini/packhound/internal/monitor"
)

// version is set at release time with -X main.version; a local build says
// what it is rather than claiming to be a release.
var version = "dev"

type options struct {
	iface     string
	mode      string
	groups    string
	joinFile  string
	joinToo   bool
	remote    string
	from      string
	session   string
	duration  time.Duration
	read      string
	out       string
	port      int
	noBrowser bool
	start     bool
	list      bool
	noUpdate  bool
	showVers  bool
}

func parseFlags() options {
	var o options
	flag.StringVar(&o.iface, "i", "", "network interface to listen on (name or index; see -list)")
	flag.StringVar(&o.mode, "mode", modeCapture, "capture (every multicast frame; needs root or Npcap), join (only the listed groups; no privileges), remote (traffic a switch mirrors here) or demo")
	flag.StringVar(&o.remote, "remote", "erspan", "with -mode remote: what the switch sends, erspan (GRE; needs root) or tzsp (UDP 37008, as MikroTik sends)")
	flag.StringVar(&o.from, "from", "", "with -mode remote: only take mirrored traffic from this switch address")
	flag.StringVar(&o.session, "session", "", "with -mode remote: only this ERSPAN session ID")
	flag.StringVar(&o.groups, "join", "", "groups to join, comma separated, e.g. 239.1.1.1-40:5000,[ff02::fb]:5353")
	flag.StringVar(&o.joinFile, "join-file", "", "file listing groups to join, one per line")
	flag.BoolVar(&o.joinToo, "send-joins", true, "in capture mode, also join the listed groups so snooping switches forward them")
	flag.DurationVar(&o.duration, "duration", 0, "listen this long without the console, then print the streams and exit")
	flag.StringVar(&o.read, "read", "", "read a capture file (pcap or pcapng) instead of listening, print the streams and exit")
	flag.StringVar(&o.out, "out", "", "with -duration or -read: write the streams to this .csv or .json file")
	flag.IntVar(&o.port, "port", 0, "console port (default: any free port)")
	flag.BoolVar(&o.noBrowser, "no-browser", false, "do not open the console in a browser")
	flag.BoolVar(&o.start, "start", false, "start listening as soon as the console opens")
	flag.BoolVar(&o.list, "list", false, "list network interfaces and exit")
	flag.BoolVar(&o.noUpdate, "no-update-check", false, "do not ask GitHub whether a newer release exists")
	flag.BoolVar(&o.showVers, "version", false, "print the version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Packhound %s: see the multicast streams arriving at this machine.\n\n", version)
		fmt.Fprintf(os.Stderr, "With no arguments it opens a console in your browser. Options:\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nAs a background service (the appliance runs this):\n  packhound server [-config /etc/packhound/config.json] [-https :443]\n  packhound setup     first-time setup of the appliance\n  packhound passwd    set a login's password\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n  packhound\n  packhound -i eth0 -duration 30s -out streams.csv\n  packhound -read site.pcapng -out streams.json\n  packhound -i \"Ethernet 2\" -mode join -join 239.10.1.1-40:5000\n  packhound -mode remote -remote tzsp -duration 1m\n  packhound -mode demo\n")
	}
	flag.Parse()
	return o
}

func main() {
	// Subcommands for the appliance and the background service.
	if len(os.Args) > 1 {
		var err error
		handled := true
		switch os.Args[1] {
		case "server":
			err = serverMain(os.Args[2:])
		case "setup":
			err = runSetup(os.Args[2:])
		case "tty":
			err = runTTY(os.Args[2:])
		case "passwd":
			err = runPasswd(os.Args[2:])
		default:
			handled = false
		}
		if handled {
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			return
		}
	}
	o := parseFlags()
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	if o.showVers {
		fmt.Println("Packhound", version)
		return nil
	}
	if flag.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q (see -h)", flag.Arg(0))
	}
	switch o.mode {
	case modeCapture, modeJoin, modeRemote, modeDemo:
	default:
		return fmt.Errorf("-mode must be capture, join, remote or demo, not %q", o.mode)
	}
	if o.joinFile != "" {
		b, err := os.ReadFile(o.joinFile)
		if err != nil {
			return err
		}
		o.groups = strings.TrimSpace(o.groups + "\n" + string(b))
	}
	if o.list {
		return listInterfaces()
	}
	if o.iface == "" && o.mode != modeDemo {
		if ifs, err := capture.Interfaces(); err == nil && len(ifs) > 0 {
			o.iface = ifs[0].Name
		}
	}
	if o.read != "" {
		return readFile(o)
	}
	if o.duration > 0 {
		return runHeadless(o)
	}
	if o.out != "" {
		return fmt.Errorf("-out needs -duration or -read")
	}
	return runConsole(o)
}

func listInterfaces() error {
	ifs, err := capture.Interfaces()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "INDEX\tNAME\tSTATE\tADDRESSES")
	for _, i := range ifs {
		state := "down"
		if i.Up {
			state = "up"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", i.Index, i.Name, state, strings.Join(i.Addrs, ", "))
	}
	tw.Flush()
	if ok, why := capture.LiveAvailable(); !ok {
		fmt.Println("\nLive capture:", why)
	}
	return nil
}

func runHeadless(o options) error {
	eng := newEngine(monitor.DefaultConfig())
	req := startRequest{Iface: o.iface, Mode: o.mode, Groups: o.groups, Join: o.joinToo, Remote: o.remote, From: o.from, Session: o.session}
	if err := eng.start(req); err != nil {
		return err
	}
	st := eng.status()
	fmt.Fprintf(os.Stderr, "Listening on %s (%s) for %s; Ctrl-C to stop early\n", st.Iface, st.Mode, o.duration)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-time.After(o.duration):
	case <-sig:
	}
	eng.stop()

	return report(eng.mon.Snapshot("", 60), o.out, "15:04:05")
}

// readFile analyses a capture file and prints what it holds.
func readFile(o options) error {
	f, err := os.Open(o.read)
	if err != nil {
		return err
	}
	defer f.Close()
	v := newFileView(filepath.Base(o.read), monitor.DefaultConfig(), findFFmpeg())
	if err := readCapture(f, v, &sync.Mutex{}); err != nil {
		return fmt.Errorf("%s: %w", o.read, err)
	}
	fmt.Fprintf(os.Stderr, "%s: %s to %s (%s), %d frames, %d multicast packets\n", v.Name,
		v.First.Format("2006-01-02 15:04:05"), v.Last.Format("15:04:05"), v.Last.Sub(v.First).Round(time.Second), v.Frames, v.Packets)
	return report(v.mon.Snapshot("", 60), o.out, "15:04:05")
}

// report prints the log and the stream table, and writes them to out when
// it is set.
func report(snap monitor.Snapshot, out, stamp string) error {
	for _, l := range snap.Log {
		fmt.Fprintf(os.Stderr, "%s  %s\n", l.Time.Format(stamp), l.Message)
	}
	printTable(snap.Rows)
	if len(snap.Alerts) > 0 {
		fmt.Println()
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ALERT\tGROUP\tNAME\tMESSAGE")
		for _, a := range snap.Alerts {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.Time.Format(stamp), a.Group, a.Name, a.Message)
		}
		tw.Flush()
	}
	if out != "" {
		if err := writeOut(out, snap); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "%d streams written to %s\n", len(snap.Rows), out)
	}
	return nil
}

func printTable(rows []monitor.Row) {
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Family < rows[j].Family })
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "GROUP\tTYPE\tNAME\tSENDER\tRATE\tPKT/S\tSIZE\tERRORS\tSTATUS")
	for _, r := range rows {
		name := r.Name
		if len(name) > 40 {
			name = name[:39] + "…"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%.1f\t%d\t%s\t%s\n", r.Group, r.Type, name, r.Sender,
			monitor.FormatRate(r.BPS), r.PPS, r.AvgSize, r.Errors, r.Status)
	}
	tw.Flush()
}

func writeOut(path string, snap monitor.Snapshot) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if strings.EqualFold(filepath.Ext(path), ".json") {
		for i := range snap.Rows {
			snap.Rows[i].Spark = nil
		}
		return writeJSONFile(f, snap)
	}
	return writeCSV(f, snap.Rows)
}

func writeJSONFile(w io.Writer, snap monitor.Snapshot) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"exported": time.Now(), "rows": snap.Rows, "alerts": snap.Alerts})
}

func serverMain(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	var o serverOptions
	fs.StringVar(&o.config, "config", defaultConfigPath, "configuration file")
	fs.StringVar(&o.state, "state", defaultStateDir, "state directory: TLS certificate and recordings")
	fs.StringVar(&o.https, "https", ":443", "address for the console, API and metrics, over HTTPS")
	fs.StringVar(&o.http, "http", ":80", "address that redirects plain HTTP to HTTPS (empty: none)")
	fs.StringVar(&o.snmpAddr, "snmp", "", "address for the SNMP agent (default: the configured port)")
	fs.Parse(args)
	return runServer(o)
}
