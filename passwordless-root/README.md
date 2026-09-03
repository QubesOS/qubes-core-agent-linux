Passwordless root
-----------------

Disables any authentication for root user in App VM.

In Qubes VMs there is no point in isolating the root account from
the user account. This is because all the user data are already
accessible from the user account, so there is no direct benefit for
the attacker if she could escalate to root.

At the same time allowing for easy user-to-root escalation in a VM
is simply convenient for users, especially for update installation.


Sudoers
-------

`qubes.sudoers` - grants the default user permission to run any commands
as root without being prompted for password.


Polkit
------

TODO


PAM
---

For Debian only. TODO
