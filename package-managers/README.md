Package managers
================

Each Qubes VM should notify Qubes updater in dom0 of new updates
available for the particular template or standalone VM.
This is the configuration and hooks for various package managers to
interact with Qubes updater. Moreover Qubes OS dom0 updates are
downloaded by a Qubes VM, rather directly in dom0 which doesn't have
networking configured at all.

dom0 updates download
---------------------

`qubes-download-dom0-updates.sh` handles downloading packages for dom0
in VM. It needs to be installed in VM which will handle dom0 updates
download only.

App VM
------

Below is the list of universal scripts intended to be installed for all
distributions. The `upgrades-installed-check`  script should be extended
with support for any new package manager that is used by a App VM.

- `upgrades-installed-check` - Checks whether there are any pending
  upgrades for various distributions.
- `upgrades-status-notify` - Notifies dom0 of any pending upgrades.

Apt
---

Below is the list of Apt specific files and configuration.

- `apt-conf-00notify-hook` - Hook to notify dom0.
- `apt-conf-70no-unattended` - Disables unattended upgrades. We don't
  want to App VM instances to upgrade themselves. And the upgrades
  installation is managed by Qubes updater.
- `apt-qubes-archive-keyring.gpg` - Qubes public GPG key signing Qubes
  deb packages.
- `apt-qubes-r4.list.in`- List of repos with Qubes packages for VM.

DNF/Yum
-------

Below is the list of DNF and Yum specific files and configuration.

- `dnf-qubes-hooks.conf`
- `dnf-qubes-hooks.py`
- `qubes-download-dom0-updates.sh`
- `RPM-GPG-KEY-qubes-4-centos`
- `RPM-GPG-KEY-qubes-4-primary`
- `RPM-GPG-KEY-qubes-4-unstable`
- `yum-qubes-hooks.conf`
- `yum-qubes-hooks.py`
- `yum-qubes-r4.repo.in`
