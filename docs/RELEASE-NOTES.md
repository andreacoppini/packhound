First release of Packhound: see the multicast streams arriving at a network port.

- **Every multicast stream on the port**, with its type, name, sender, bit rate, packet rate, packet size, jitter, errors and health, refreshed every second.
- **IPTV**: MPEG-TS over UDP or RTP, with the channel name from the SDT, the PIDs and their rates, H.264 picture size, continuity-counter errors, RTP losses and the Media Delivery Index.
- **Audio**: AES67 and other RTP audio, named from SAP announcements.
- **Discovery and control**: mDNS (services announced), SSDP/UPnP (devices), WS-Discovery, LLMNR, SAP, PTP (grandmaster), IGMP (querier, memberships), VRRP and HSRP.
- **IPv6** on its own tab: neighbour discovery, router adverts, MLD, mDNS.
- **Alerts** when a video or audio stream stops, drops below its usual rate, shows errors or gains a second sender.
- **Two ways to listen**: capture everything on the port (root on Linux and macOS, Npcap on Windows), or join listed groups with no privileges or drivers.
- **Record** to a pcap file for Wireshark; export the table as CSV or JSON.
- **Demo mode** to try the console with no network.

Downloads are below. There is no installer: unzip and run.

**Virtual appliance.** `packhound-appliance-*.ova` (VMware, VirtualBox), `.qcow2` (Proxmox, KVM) and `-hyperv.zip` (Hyper-V): a minimal Debian that runs Packhound around the clock.

- A short setup on the VM console: address (DHCP or static), host name, login. Everything else is in the web console.
- The web console behind a login, over HTTPS. What you start keeps running, and resumes after a reboot.
- **SNMP v1/v2c agent** with `PACKHOUND-MIB`: per-stream name, status, rate, packet rate, jitter and errors, indexed by group and port, ready for The Dude and other managers.
- **REST API** (`/api/v1/...`) with a token, and Prometheus metrics at `/metrics`.
- Network, host name, time, SSH, reboot and shutdown from Settings.
