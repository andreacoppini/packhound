**Packhound 1.3.0: capture files and remote switches.**

- **Open a capture file:** **Open capture…** analyses a `.pcap` or `.pcapng` from Wireshark or tcpdump in a view of its own, while live monitoring (and on the appliance, SNMP and the REST API) carries on. The result is the state of things when the capture ended: rates averaged over the capture, errors totalled, alerts as a timeline in the capture's own times, and a mosaic still of each channel taken from the file. Captures of a switch's mirror are unwrapped. From the command line: `packhound -read site.pcapng -out streams.json`.
- **Watch a switch you are not plugged into:** the new **Remote switch** mode receives a port mirror over the network, as ERSPAN (Types I, II and III, or plain GRE: Cisco, Arista, Juniper, Aruba, Ruckus ICX) or as TZSP (MikroTik's sniffer streaming). The console shows configuration examples with Packhound's address filled in, and says whether the mirror is arriving and from which switch. ERSPAN needs root (the appliance runs as root); TZSP needs nothing.

Earlier notes follow.

**Packhound 1.2.2:** the mosaic's refresh interval can be set to 15 seconds, 30 seconds (the new default) or one minute, from the top of the mosaic page; the appliance remembers it. Stills are taken only while the mosaic page is open or the API is being polled, and stop a minute after the last request (it was five). Earlier notes follow.

**Packhound 1.2.1** fixes the mosaic for channels whose encoders send open GOPs: their key pictures are I-frames marked as recovery points rather than IDR frames, and 1.2.0 could not decode them. Radio channels are now labelled as radio rather than "no video". 1.2.0's notes follow.

**Packhound 1.2.0: the mosaic.**

- **Mosaic:** a page, opened from **Mosaic** in the console's header in a new tab, with a still of every MPEG-TS channel every 15 seconds to a minute. Each tile shows the channel's name, its state, its errors, how old the picture is, and a speaker: green while audio is arriving, red when the channel has audio but none is arriving. Scrambled channels and channels that stop are marked as such.
- **Light on the CPU:** a still is the next key picture on the channel, taken from the stream Packhound already receives (no extra joins), and decoded by ffmpeg one at a time, using at most a quarter of one core. Stills are taken only while the mosaic is open or being read by an API client.
- **REST API, for monitoring systems and dashboards:** `GET /api/v1/mosaic` lists the channels with their stills, and `GET /api/v1/mosaic/<group:port>.jpg` serves each one (JPEG, 320 pixels wide, with ETag). With `?token=`, the image URLs carry the token, so a client that can only fetch a URL can show them.
- **Wall screen:** `https://<appliance>/mosaic?token=<API token>` opens the mosaic without logging in. The token never opens the console.

The appliance now includes a small ffmpeg (H.264, HEVC and MPEG-2, LGPL). On Windows, macOS and Linux, Packhound uses an ffmpeg beside it or on the PATH; without one, the mosaic shows each channel's state and audio, but no pictures.

**Downloads:** Windows, macOS and Linux builds, and the virtual appliance as `.ova` (VMware, VirtualBox), `.qcow2` (Proxmox, KVM) and `-hyperv.zip` (Hyper-V). There is no installer: unzip and run, or import the appliance.
