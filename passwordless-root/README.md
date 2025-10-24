# Passwordless in-qubqube admin authorization

By default all users in the `qubes` group (usually only the standard `user`
user) are allowed to execute things as root via sudo/su/pkexec. This is allowed
without a password prompt.

Separating the user isn't that meaningfull since Qubes' primary
compartimentalization layer are qubes and `user` in a qube has access most
things there anyway (user data, GUI I/O, etc). But some advanced users want
more options therefore this mechanism has been extended.

## Modes

There are 3 modes:

 - `allow`: Always allow admin access.
 - `deny`: Always deny admin access.
 - `qrexec`: Make a qrexec call and use it's result to allow/deny. The main
   usage is to have a trivial qrexec service in dom0 and use the qrexex policy
   with the ask action to allow only after prompting.

"Admin access" here means being able to run things as another user (including
root), via sudo, su and polkit. This is always limited to users in the `qubes`
group.


## Config

When the `qubes-core-agent-passwordless-root` is installed the
pam_qubes_admin_authz.so is always enabled. This module asks the
`qubes-admin-authzd` daemon which does the actual logic (see below for
technical details).

The mode can be set via /usr/local/etc/qubes/admin-authzd.conf for per-qube
setting or more common via /etc/qubes/admin-authzd.conf in a template (setting
in /usr/local has precendce).

There config file have a very simpley syntax. The first line needs to contain
one of the listed mode above without anythings else. Currently the rest of the
file is ignored. Please prefix comments with `#` to allow extension of this
configuration file should the need arise.


## qrexec policy

After setting the mode to qrexec, you need to configure the qrexec policy in
dom0. For example:

```
qubes.AuthorizeInVMAdminAccess * * @default ask target=dom0 default_target=dom0
```

asks for requests from any VM.

Note that in dom0 only a trivial service is run that returns a fixed string
such that the qube knows the result of the policy evaluation. The idea here is
that this way the existing qrexec policy can be reused, including it's ask
prompt.


## Limitaions

Keep in mind that if you have allowed admin access and the qube was compromised
at that point persistence is trivial.


## Technical details

We implement a PAM module named `pam_qubes_admin_authz.so` to permit the
access. Since PAM modules can be run in a setuid context (when called by
sudo/su) we want to keep the code simple there. Therefore we use just some
existing PAM helper functions to check for the requsting users group membership
and check the PAM "service" (`sudo`, `su-l`, etc.) and if they match we make a
connection to an abstract unix socket. With `SO_PEERCRED` we check that this
socket has been opened by root. The rest, including config file handling and
invoking qrexec-client-vm is then handled by the `qubes-admin-authzd` at the
other end of the socket (started by qubes-admin-authzd.service).

## Recovery

Should you have locked you self out you should still be able to use
`qvm-console-dispvm` and login as root there without a password.
