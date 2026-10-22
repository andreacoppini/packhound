# Packhound

Sniffs out every multicast stream arriving at a network port and tells you what
it is, how fast it runs, who is sending it and whether it is healthy: IPTV
channels, AES67 audio, mDNS, SSDP, PTP, IGMP and the rest of a network's
chatter. One binary, no installer, a console in your browser.

> Author: Andrea Coppini · Feedback: <andrea@tacoppini.com>

![The Packhound console](docs/console.png)

## Download

Get the file for your platform from the
[latest release](https://github.com/andreacoppini/packhound/releases/latest):

| Platform | File |
|---|---|
| Windows | `packhound-windows-amd64.exe` (`-arm64` for Surface and Snapdragon), or the `.zip` of the same file for networks that block `.exe` downloads |
| macOS | `packhound-macos.zip`, one universal binary for Intel and Apple Silicon |
| Linux | `packhound-linux-amd64.tar.gz` (or `-arm64`) |

The binaries are unsigned, so Windows and macOS warn on first launch. On macOS
run `xattr -d com.apple.quarantine packhound-macos-universal` once, or
right-click and Open. `SHA256SUMS.txt` in the release covers every file, and
every binary is built by [GitHub Actions](.github/workflows/release.yml) from
the tagged commit.

To build it yourself you need only Go: `go build .`

## Using it

Run it with no arguments, or double-click it, and it opens the console in your
browser, bound to this machine only:

```
Packhound 1.0.0
Console: http://127.0.0.1:52413
```

Pick the interface, choose how to listen, press **Listen**. Choose **Demo** to
see the console working with made-up traffic and no network at all.

### Two ways to listen

| | Capture everything | Join groups only |
|---|---|---|
| Sees | every multicast frame the port receives, including IGMP, VRRP, PIM, MLD and other non-UDP protocols | only the groups you list, and only their UDP payloads |
| Needs | **Linux:** root, or `sudo setcap cap_net_raw,cap_net_admin+ep ./packhound` once<br>**macOS:** root, or Wireshark's ChmodBPF helper<br>**Windows:** [Npcap](https://npcap.com) (free) | nothing: no driver, no admin rights |
| Puts the interface in | all-multicast mode (Linux) or promiscuous mode (macOS, Windows) | its normal state |

If capture is not available, Packhound says why and falls back to joining the
listed groups.

**Capture does not make the switch send you anything.** On a switch with IGMP
snooping, a group only reaches your port if something on that port has joined
it. That is what the *Groups to join* list is for: in capture mode, Packhound
also joins the groups listed there, so you can pull an IPTV channel to the port
and watch it. Link-local groups (224.0.0.x, ff02::) and anything the switch
floods arrive regardless.

Groups are listed one per line as a group and UDP port. Ranges and blocks
work, and IPv6 goes in brackets:

```
239.10.1.1-239.10.1.40:5000
239.10.1.1-40:5000          # the same range, written short
239.10.2.0/28:5004
[ff02::fb]:5353
```

**Add discovery groups** fills in mDNS, SSDP, WS-Discovery, LLMNR, SAP and PTP.

### What each column means

| Column | |
|---|---|
| Group | the multicast group, and the UDP port where there is one |
| Type | what the traffic is, from the port and the payload (an MPEG-TS sync byte every 188 bytes, an RTP header, a known discovery protocol) |
| Name | the channel name (from the stream's SDT), the AES67 session (from SAP), or a summary (*8 services, 6 types*) |
| Rate | bits per second at the IP layer, which is what the stream costs on the wire; the payload rate is in the detail panel |
| Packets/s, Avg size | per second, and the IP datagram size: 1,344 bytes is seven TS packets over UDP, 1,356 the same over RTP |
| Jitter | how much the gap between packets varies, for video and audio |
| Errors | continuity-counter errors (MPEG-TS) and lost packets (RTP) in the last minute |
| Status | **Receiving**, **Degraded** (errors, or a rate well below its usual), **Lost** (silent for longer than the alert setting), or for protocols that speak when they have something to say, **Periodic** and **Quiet** |

Click a row for its detail: a rate graph over the last minute, ten minutes or
hour, and what the protocol says.

- **IPTV:** each programme's name, provider and type; the PIDs with their
  content, language and rate; the picture size read from the H.264 stream;
  continuity errors per PID; the Media Delivery Index (delay factor and loss
  rate, RFC 4445); RTP losses and reordering.
- **AES67 and RTP audio:** format, packet time and sender, named from SAP.
- **mDNS:** every service announced (AirPlay, Chromecast, printers, Sonos,
  HomeKit and so on) with its host, address and port, and what is being asked
  for.
- **SSDP and WS-Discovery:** devices, their server strings and description URLs.
- **PTP:** the grandmaster, its clock class, accuracy and priority, and the
  message rates.
- **IGMP and MLD:** the elected querier and its interval, and who has joined what.
- **VRRP and HSRP:** the active router, its priority and the virtual addresses;
  two VRRP routers advertising the same group is flagged as a split brain.
- **IPv6 neighbour discovery:** routers advertising, their prefixes and DNS,
  and the addresses being resolved.
- **Anything unrecognised:** the first bytes of the payload.

IPv6 streams are on their own tab, so the table you care about is not buried
under neighbour discovery.

### Alerts

A video or audio stream raises an alert when it stops, when it degrades, when
it recovers, and when a second sender appears on it (usually a misconfigured
encoder or a loop). The thresholds are in the sidebar and apply immediately.
Discovery and control protocols are never alarmed.

### Recording and exporting

**Record** writes the multicast traffic to a `.pcap` file for Wireshark, in your
Downloads folder; stopping the recording downloads it. In capture mode the
frames are written as received; in join mode the socket never saw the headers,
so the frames are rebuilt around the payloads. Recordings stop at 2 GB.

**CSV** and **JSON** download the stream table; JSON includes the alerts.

### From the command line

The same engine runs without the console:

```
packhound -list                                   # interfaces, and whether capture works here
packhound -i eth0 -duration 30s -out streams.csv  # listen, print the table, save it
packhound -i "Ethernet 2" -mode join -join 239.10.1.1-40:5000 -duration 1m
packhound -i en0 -join-file channels.txt -start   # console, already listening
packhound -mode demo
```

`packhound -h` lists every option.

### Update check

On launch it asks GitHub once whether a newer release exists and shows a badge
if so. It never delays anything, says nothing when it fails, and caches the
answer for a day. `-no-update-check` or `PACKHOUND_NO_UPDATE_CHECK=1` turns it
off.

## How it works

Capture uses no C code on any platform: an AF_PACKET socket on Linux, a BPF
device on macOS, and Npcap's `wpcap.dll` loaded at run time on Windows. A
kernel filter passes only group-addressed frames, so a busy port's unicast
costs nothing. Join mode uses ordinary UDP sockets, one per group.

The packages:

| | |
|---|---|
| `internal/pkt` | Ethernet, VLAN, IPv4 (with fragments), IPv6 (with extension headers), UDP |
| `internal/capture` | live capture per platform, and joined sockets |
| `internal/monitor` | streams, rates, health, alerts, and a decoder per protocol |
| `internal/mpegts` | transport stream analysis: PSI tables, continuity, H.264 picture size |
| `internal/demo` | the demo traffic, built from real frames |
| `web/` | the console, embedded in the binary |

Live capture has been tested on Linux. The macOS and Windows capture code builds
and is checked on every push, but has not yet been run against real hardware;
join mode works the same on all three.

## Changelog

What's new in 1.0.0 (2026-10-22):

```
*) First release: live multicast monitor for IPTV, audio, discovery,
   timing and routing protocols, IPv4 and IPv6, with alerts, pcap
   recording, CSV/JSON export and a demo mode.
```

## Licence

GPL-3.0. See [LICENSE](LICENSE).
