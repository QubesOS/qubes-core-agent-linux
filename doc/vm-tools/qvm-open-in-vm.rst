==============
qvm-open-in-vm
==============

NAME
====
qvm-open-in-vm - open a specified file or URL in a other VM

SYNOPSIS
========
| qvm-open-in-vm [--view-only] [vmname] filename
| qvm-open-in-vm [vmname] URL
| qvm-open-in-vm vmname file|directory...

If *vmname* is omitted, it defaults to ``@default`` and the qrexec policy
decides which VM the file or URL is opened in.

A single file is opened with the ``qubes.OpenInVM`` service, and the changes
made to it are sent back. Several files, or a directory, are copied with the
``qubes.OpenFilesInVM`` service to a new directory in
``~/QubesIncoming/<source VM>`` in the target VM. There, files are grouped by
default application, each application is started once with all its files, and
a directory is shown in the file manager. These files are read-only and the
changes made to them are not sent back.

OPTIONS
=======

--view-only
    Do not send changes back. Always the case when opening several files or a
    directory.

AUTHORS
=======
| Joanna Rutkowska <joanna at invisiblethingslab dot com>
| Rafal Wojtczuk <rafal at invisiblethingslab dot com>
| Marek Marczykowski <marmarek at invisiblethingslab dot com>
