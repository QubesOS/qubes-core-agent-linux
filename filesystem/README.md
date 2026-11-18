Filesystem
----------

Defines filesystem layout for VM-s. Apart from rootfs, which is not
persistent for App VM instances, there's read-write filesystem mounted
for `/home/` and `/usr/local`.

Bind-dirs
---------

`30_cron.conf` defines bind-dir for directory where cron keeps state.
This is needed to avoid duplicate run of jobs.

To learn more about bind-dirs, see
[How to make any file in a TemplateBasedVM persistent
using bind-dirs](https://www.qubes-os.org/doc/bind-dirs/) in [User
Documentation](https://www.qubes-os.org/doc/#user-documentation).
