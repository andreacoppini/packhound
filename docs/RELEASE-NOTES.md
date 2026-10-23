**Packhound 1.2.1** fixes the mosaic for channels whose encoders send open GOPs: their key pictures are I-frames marked as recovery points rather than IDR frames, and 1.2.0 could not decode them. Radio channels are now labelled as radio rather than "no video". 1.2.0's notes follow.

**Packhound 1.2.0: the mosaic.**

- **Mosaic:** a page, opened from **Mosaic** in the console's header in a new tab, with a still of every MPEG-TS channel about every 10 seconds. Each tile shows the channel's name, its state, its errors, how old the picture is, and a speaker: green while audio is arriving, red when the channel has audio but none is arriving. Scrambled channels and channels that stop are marked as such.
- **Light on the CPU:** a still is the next key picture on the channel, taken from the stream Packhound already receives (no extra joins), and decoded by ffmpeg one at a time, using at most a quarter of one core. Stills are taken only while the mosaic is open or being read by an API client.
- **REST API, for monitoring systems and dashboards:** `GET /api/v1/mosaic` lists the channels with their stills, and `GET /api/v1/mosaic/<group:port>.jpg` serves each one (JPEG, 320 pixels wide, with ETag). With `?token=`, the image URLs carry the token, so a client that can only fetch a URL can show them.
- **Wall screen:** `https://<appliance>/mosaic?token=<API token>` opens the mosaic without logging in. The token never opens the console.

The appliance now includes a small ffmpeg (H.264, HEVC and MPEG-2, LGPL). On Windows, macOS and Linux, Packhound uses an ffmpeg beside it or on the PATH; without one, the mosaic shows each channel's state and audio, but no pictures.

**Downloads:** Windows, macOS and Linux builds, and the virtual appliance as `.ova` (VMware, VirtualBox), `.qcow2` (Proxmox, KVM) and `-hyperv.zip` (Hyper-V). There is no installer: unzip and run, or import the appliance.
