// Package groups parses the list of multicast groups to join, as typed into
// the console or passed on the command line.
//
// One entry per line (or separated by commas or spaces), each a group and a
// UDP port:
//
//	239.10.1.1:5000
//	239.10.1.1-239.10.1.40:5000   a range
//	239.10.1.1-40:5000            the same, last octet only
//	239.10.2.0/28:5004            a block
//	[ff02::fb]:5353               IPv6 in brackets
//	# comments run to the end of the line
package groups

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Max is the most groups one list may expand to. Each joined group costs a
// socket, and a typo in a range should not open sixty thousand.
const Max = 1024

// Group is one group and UDP port to join.
type Group struct {
	Addr netip.Addr
	Port uint16
}

func (g Group) String() string {
	return netip.AddrPortFrom(g.Addr, g.Port).String()
}

// Common lists discovery and timing groups that every site has, for one-click
// adding in join mode: mDNS, SSDP, WS-Discovery, LLMNR, SAP and PTP.
const Common = `224.0.0.251:5353   # mDNS
239.255.255.250:1900   # SSDP / UPnP
239.255.255.250:3702   # WS-Discovery
224.0.0.252:5355   # LLMNR
239.255.255.255:9875   # SAP (AES67 announcements)
224.0.1.129:319   # PTP event
224.0.1.129:320   # PTP general
[ff02::fb]:5353   # mDNS over IPv6`

// Parse reads a list. It reports every bad line, not just the first.
func Parse(text string) ([]Group, error) {
	var out []Group
	seen := map[Group]bool{}
	var errs []string
	for n, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, f := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == ';' }) {
			gs, err := parseEntry(f)
			if err != nil {
				errs = append(errs, fmt.Sprintf("line %d: %s", n+1, err))
				continue
			}
			for _, g := range gs {
				if !seen[g] {
					seen[g] = true
					out = append(out, g)
				}
			}
			if len(out) > Max {
				return nil, fmt.Errorf("more than %d groups; narrow the ranges", Max)
			}
		}
	}
	if len(errs) > 0 {
		return out, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return out, nil
}

func parseEntry(s string) ([]Group, error) {
	var host, portStr string
	switch {
	case strings.HasPrefix(s, "["):
		i := strings.Index(s, "]:")
		if i < 0 {
			return nil, fmt.Errorf("%q: an IPv6 group needs a port, as [ff02::fb]:5353", s)
		}
		host, portStr = s[1:i], s[i+2:]
	default:
		i := strings.LastIndexByte(s, ':')
		if i < 0 || strings.Count(s, ":") > 1 {
			return nil, fmt.Errorf("%q needs a port, as 239.1.1.1:5000", s)
		}
		host, portStr = s[:i], s[i+1:]
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("%q: bad port %q", s, portStr)
	}

	addrs, err := expand(host)
	if err != nil {
		return nil, fmt.Errorf("%q: %v", s, err)
	}
	out := make([]Group, 0, len(addrs))
	for _, a := range addrs {
		if !a.IsMulticast() {
			return nil, fmt.Errorf("%s is not a multicast address", a)
		}
		out = append(out, Group{Addr: a, Port: uint16(port)})
	}
	return out, nil
}

func expand(host string) ([]netip.Addr, error) {
	if strings.Contains(host, "/") {
		p, err := netip.ParsePrefix(host)
		if err != nil {
			return nil, err
		}
		p = p.Masked()
		if p.Addr().BitLen()-p.Bits() > 10 {
			return nil, fmt.Errorf("block too large (at most %d addresses)", Max)
		}
		var out []netip.Addr
		for a := p.Addr(); p.Contains(a); a = a.Next() {
			out = append(out, a)
		}
		return out, nil
	}
	if i := strings.IndexByte(host, '-'); i >= 0 {
		from, err := netip.ParseAddr(host[:i])
		if err != nil {
			return nil, err
		}
		toStr := host[i+1:]
		// "239.1.1.1-40": the end shares all but the last octet.
		if from.Is4() && !strings.Contains(toStr, ".") {
			n, err := strconv.Atoi(toStr)
			if err != nil || n < 0 || n > 255 {
				return nil, fmt.Errorf("bad range end %q", toStr)
			}
			b := from.As4()
			b[3] = byte(n)
			toStr = netip.AddrFrom4(b).String()
		}
		to, err := netip.ParseAddr(toStr)
		if err != nil {
			return nil, err
		}
		if to.Less(from) {
			return nil, fmt.Errorf("range runs backwards")
		}
		var out []netip.Addr
		for a := from; a.Compare(to) <= 0; a = a.Next() {
			out = append(out, a)
			if len(out) > Max {
				return nil, fmt.Errorf("range too large (at most %d addresses)", Max)
			}
		}
		return out, nil
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}
	return []netip.Addr{a}, nil
}
