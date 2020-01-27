Package managers
================

Each Qubes VM should notify Qubes updater in dom0 of new updates
available for the particular template or standalone VM.
The is the configuration and hooks for various package managers to
interact with Qubes updater. Moreover Qubes OS dom0 updates are
downloaded by a Qubes VM, rather directly in dom0 which doesn't have
networking configured at all.

dom0 updates download
---------------------

`qubes-download-dom0-updates.sh` handles downloading packages for dom0
in VM. It needs to be installed in VM which will handle dom0 updates
download only.

Apt
---

The configuration includes:

1. Hook to notify dom0.
2. Disabling unattended upgrades (Qubes updater).
3. List of repos with Qubes packages for VM.
