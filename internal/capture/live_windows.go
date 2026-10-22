package capture

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/windows"
)

// Windows: Npcap's wpcap.dll, loaded at run time so that the binary needs no
// C toolchain to build and still starts on machines without Npcap (which then
// fall back to joining groups).

var npcap struct {
	once sync.Once
	err  error

	create, setSnaplen, setPromisc, setTimeout, setImmediate, setBuffer,
	activate, setfilter, nextEx, datalink, close, geterr *windows.Proc
}

const npcapMissing = "live capture on Windows needs Npcap, free from https://npcap.com (tick \"WinPcap API-compatible mode\" when installing)"

func loadNpcap() error {
	npcap.once.Do(func() {
		sys, err := windows.GetSystemDirectory()
		if err != nil {
			npcap.err = err
			return
		}
		dir := filepath.Join(sys, "Npcap")
		// wpcap.dll loads Packet.dll from the same folder.
		_ = windows.SetDllDirectory(dir)
		dll, err := windows.LoadDLL(filepath.Join(dir, "wpcap.dll"))
		if err != nil {
			// WinPcap-compatible installs also put it on the system path.
			if dll, err = windows.LoadDLL("wpcap.dll"); err != nil {
				npcap.err = errors.New(npcapMissing)
				return
			}
		}
		for _, p := range []struct {
			name string
			dst  **windows.Proc
		}{
			{"pcap_create", &npcap.create}, {"pcap_set_snaplen", &npcap.setSnaplen},
			{"pcap_set_promisc", &npcap.setPromisc}, {"pcap_set_timeout", &npcap.setTimeout},
			{"pcap_set_immediate_mode", &npcap.setImmediate}, {"pcap_set_buffer_size", &npcap.setBuffer},
			{"pcap_activate", &npcap.activate}, {"pcap_setfilter", &npcap.setfilter},
			{"pcap_next_ex", &npcap.nextEx}, {"pcap_datalink", &npcap.datalink},
			{"pcap_close", &npcap.close}, {"pcap_geterr", &npcap.geterr},
		} {
			if *p.dst, err = dll.FindProc(p.name); err != nil {
				npcap.err = fmt.Errorf("wpcap.dll is too old (no %s): update Npcap from https://npcap.com", p.name)
				return
			}
		}
	})
	return npcap.err
}

func liveAvailable() (bool, string) {
	if err := loadNpcap(); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// platformNames finds the Npcap device name for each interface: Npcap names
// adapters \Device\NPF_{GUID}, the GUID being the adapter name Windows uses
// internally.
func platformNames(ifs []Interface) {
	size := uint32(16 << 10)
	for tries := 0; tries < 3; tries++ {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0, aa, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return
		}
		for a := aa; a != nil; a = a.Next {
			guid := windows.BytePtrToString(a.AdapterName)
			for i := range ifs {
				if ifs[i].Index == int(a.IfIndex) {
					ifs[i].device = `\Device\NPF_` + guid
				}
			}
		}
		return
	}
}

type pcapPkthdr struct {
	Sec    int32
	Usec   int32
	Caplen uint32
	Len    uint32
}

type bpfProgram struct {
	Len   uint32
	Insns *bpf.RawInstruction
}

type npcapSource struct {
	p      uintptr
	link   int
	closed atomic.Bool
	done   atomic.Bool
}

func cstr(s string) *byte {
	b, _ := windows.BytePtrFromString(s)
	return b
}

func (n *npcapSource) lastError() string {
	r, _, _ := npcap.geterr.Call(n.p)
	// r is a C string owned by Npcap; reading it through a pointer to the
	// uintptr keeps the conversion within the rules vet checks.
	return windows.BytePtrToString(*(**byte)(unsafe.Pointer(&r)))
}

func openLive(ifc Interface) (Source, error) {
	if err := loadNpcap(); err != nil {
		return nil, err
	}
	if ifc.device == "" {
		return nil, fmt.Errorf("Npcap has no device for %s", ifc.Name)
	}
	var errbuf [512]byte
	p, _, _ := npcap.create.Call(uintptr(unsafe.Pointer(cstr(ifc.device))), uintptr(unsafe.Pointer(&errbuf[0])))
	if p == 0 {
		return nil, fmt.Errorf("Npcap cannot open %s: %s", ifc.Name, windows.BytePtrToString(&errbuf[0]))
	}
	n := &npcapSource{p: p}
	npcap.setSnaplen.Call(p, 65535)
	// Without promiscuous mode the adapter's own multicast filter drops the
	// groups this machine has not joined.
	npcap.setPromisc.Call(p, 1)
	npcap.setTimeout.Call(p, 250)
	npcap.setImmediate.Call(p, 1)
	npcap.setBuffer.Call(p, 32<<20)
	if r, _, _ := npcap.activate.Call(p); int32(r) < 0 {
		msg := n.lastError()
		npcap.close.Call(p)
		if int32(r) == -8 { // PCAP_ERROR_PERM_DENIED
			return nil, errors.New("Npcap refused: it was installed for administrators only, so run Packhound as administrator")
		}
		return nil, fmt.Errorf("Npcap cannot start capture on %s: %s", ifc.Name, msg)
	}
	r, _, _ := npcap.datalink.Call(p)
	n.link = int(int32(r))
	if n.link == 1 {
		prog, err := bpf.Assemble([]bpf.Instruction{
			bpf.LoadAbsolute{Off: 0, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 1, SkipTrue: 0, SkipFalse: 1},
			bpf.RetConstant{Val: 1 << 18},
			bpf.RetConstant{Val: 0},
		})
		if err == nil {
			fp := bpfProgram{Len: uint32(len(prog)), Insns: &prog[0]}
			npcap.setfilter.Call(p, uintptr(unsafe.Pointer(&fp)))
		}
	}
	return n, nil
}

func (n *npcapSource) Next() (Frame, error) {
	for {
		if n.closed.Load() {
			n.finish()
			return Frame{}, ErrClosed
		}
		var hdr *pcapPkthdr
		var data *byte
		r, _, _ := npcap.nextEx.Call(n.p, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data)))
		switch int32(r) {
		case 1:
			b := unsafe.Slice(data, hdr.Caplen)
			return Frame{Data: b, Link: n.link, Time: time.Unix(int64(hdr.Sec), int64(hdr.Usec)*1000)}, nil
		case 0:
			continue // read timeout
		default:
			msg := n.lastError()
			n.finish()
			if n.closed.Load() {
				return Frame{}, ErrClosed
			}
			return Frame{}, fmt.Errorf("Npcap: %s", msg)
		}
	}
}

// finish releases the handle; only the reading goroutine does this, so it
// can never close the handle under a read in progress.
func (n *npcapSource) finish() {
	if !n.done.Swap(true) {
		npcap.close.Call(n.p)
	}
}

func (n *npcapSource) Close() error {
	n.closed.Store(true)
	return nil
}
