**Packhound 1.1.0: Dante.**

- **Dante multicast flows** are named after the device that sends them, so a device's flows sort together.
- **Dante's clock:** PTPv1, which Dante uses unless in AES67 mode, is decoded beside PTPv2: the clock leader's ID, address and device name, its stratum and identifier, and the sync interval.
- **Dante devices** and the number of channels each announces are listed from their mDNS announcements, and Dante's services are named.
- **Sender names:** wherever a sender announces a name over mDNS, it appears beside its address in the table, the senders list, and the API (`senderName`).

Native Dante audio uses its own format, so a flow shows rate, packets, jitter and whether it stops, but not channel content. Dante sends audio unicast unless a flow is set to multicast, and unicast flows are not visible to a multicast monitor.

**Downloads:** Windows, macOS and Linux builds, and the virtual appliance as `.ova` (VMware, VirtualBox), `.qcow2` (Proxmox, KVM) and `-hyperv.zip` (Hyper-V). There is no installer: unzip and run, or import the appliance.
