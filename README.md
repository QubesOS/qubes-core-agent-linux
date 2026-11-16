# Qubes Core Agent for Linux

This is the core agent that runs inside Linux qubes in [Qubes OS](https://www.qubes-os.org).
It is installed in templates and other Linux qubes to integrate them with the rest of the system.

It is built as RPM, Debian and Arch Linux packages.
The main package is `qubes-core-agent`.
Other parts are in separate `qubes-core-agent-*` packages.
On Arch Linux the packages are named `qubes-vm-*` instead.

The services and settings it reads from dom0 are described in the
[VM configuration interface](https://www.qubes-os.org/doc/vm-interface/) documentation.
See the [Qubes OS documentation](https://www.qubes-os.org/doc/) for more.

## Parts

- `qubes-rpc/`: qrexec services that dom0 and other qubes call in this qube.
  They cover file copy, open in VM, start apps, run commands, backup and restore, clock sync, suspend, app menus and more.
  It also has the tools that call such services from inside the qube, like `qvm-copy`, `qvm-move`, `qvm-open-in-vm`, `qvm-open-in-dvm` and `qvm-run-vm`.
  The C helpers that send and receive copied files are here too.
  Most of it is in the main package.
  - `qubes-rpc/nautilus/`, `caja/`, `thunar/`, `pcmanfm-qt/`, `kde/`: file manager menu entries to copy or move files to another qube, or open them in a disposable.
    Nautilus, Caja and Thunar each have their own package.
    PCManFM-Qt has its own package on Debian only.
    The KDE entries are in the main package.
  - `qubes-rpc/bookmark/`: adds a `~/QubesIncoming` bookmark for GTK file managers (`qubes-core-agent-bookmark`).
  - `qubes-rpc/post-install.d/`: scripts that `qubes.PostInstall` runs after packages are installed or updated.
    Among other things, they report the qube's features to dom0 and refresh its app menus.
    `qubes.PostUpdate` runs the scripts in `/etc/qubes/post-update.d/` after every update run.
- `qubesagent/`: Python package.
  `qubes-firewall` reads firewall rules from QubesDB and applies them with nftables (`qubes-core-agent-networking`).
  `qubes-vmexec` runs the commands for `qubes.VMExec`.
  `xdg.py` starts apps from `.desktop` files, with Qubes drop-ins applied.
- `vm-systemd/`: systemd units and the scripts they run at boot.
  They read which Qubes services are on from QubesDB, mount `/rw`, bind-mount `/home` and `/usr/local` from it, set up [bind-dirs](https://www.qubes-os.org/doc/bind-dirs/), grow the root filesystem, sync the clock and check for updates.
  Most drop-ins for distribution units make a unit start only when the matching Qubes service is on.
  On RPM systems the units are in `qubes-core-agent-systemd`, and the network units are in `qubes-core-agent-networking`.
- `init/`: shell scripts and the shared `functions` library used at boot, installed in `/usr/lib/qubes/init/`.
- `vm-init.d/`: SysV init scripts.
  The RPM and Debian packages do not ship them.
- `network/`: networking for qubes that provide or use network.
  It sets IP address, DNS and gateway from QubesDB, holds the nftables rules and Xen vif scripts, and sets up the tinyproxy updates proxy (`qubes-core-agent-networking`).
  It also has the NetworkManager hooks and config (`qubes-core-agent-network-manager`), and `qvm-connect-tcp` (main package).
- `package-managers/`: repository definitions and signing keys for Qubes packages, and hooks for apt, dnf and yum.
  The hooks and `upgrades-status-notify` tell dom0 whether updates are pending.
  The scripts that download dom0 updates in a qube are in `qubes-core-agent-dom0-updates`.
- `passwordless-root/`: sudo, polkit and `su` config that lets the user become root without a password (`qubes-core-agent-passwordless-root`).
- `filesystem/`: `/etc/fstab`, the bind-dirs entry for `/var/spool/cron`, and the `/rw` and `/mnt/removable` mount points.
- `boot/`: GRUB defaults and dracut config for booting a qube, and a short stop timeout for user sessions.
  `boot/redhat/` holds an old Upstart job for a serial console login; the RPM package installs it only where `/etc/init/serial.conf` exists.
- `app-menu/`: launchers used by the app menu and session start, like `qubes-desktop-run`, `qubes-run-terminal` and `qubes-session-autostart`.
  `qubes-trigger-sync-appmenus.sh` sends the qube's app menu entries to dom0.
- `autostart-dropins/`, `applications-dropins/`: drop-ins installed in `/etc/qubes/autostart/` and `/etc/qubes/applications/`.
  They change `.desktop` entries, for example to hide some autostart items in qubes.
  Each directory has a `README.txt` on how they work.
- `config-overrides/`: changed default settings for desktop and system tools, such as GSettings, dconf, sudo, sysctl and Qt.
- `misc/`: smaller files, among them:
  `qvm-features-request` (asks dom0 to set a feature),
  `qvm-service-wrapper` (starts a program only if a Qubes service is on),
  the MIME setup `qubes.StartApp` uses to open files in a disposable,
  a udev rule that brings hot-plugged memory online,
  and the Qubes master signing key.
- `selinux/`: SELinux policy for the agent tools (`qubes-core-agent-selinux`, RPM only).
- `doc/`: man pages for `qvm-copy`, `qvm-move`, `qvm-open-in-vm`, `qvm-open-in-dvm` and `qvm-run-vm`.

Build and test files:

- `rpm_spec/`, `debian/`, `archlinux/`: package definitions.
- `debian-quilt`, `patches.debian/`, `series-debian-*.conf`: extra patches for Debian builds.
- `Makefile`, `setup.py`, `version`, `.qubesbuilder`, `Makefile.builder`: build and install.
- `run-tests`, `test-packages/`, `ci/`, `.gitlab-ci.yml`: tests and CI.
