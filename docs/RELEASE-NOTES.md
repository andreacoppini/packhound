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
