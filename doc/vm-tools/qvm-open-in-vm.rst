.. program:: qvm-open-in-vm

==============
qvm-open-in-vm
==============

NAME
====
qvm-open-in-vm - open a specified file or URL in a other VM

SYNOPSIS
========
| qvm-open-in-vm [vmname] filename
| qvm-open-in-vm [vmname] URL

If *vmname* is omitted, it defaults to ``@default`` and the qrexec policy
decides which VM the file or URL is opened in.

OPTIONS
=======

AUTHORS
=======
| Joanna Rutkowska <joanna at invisiblethingslab dot com>
| Rafal Wojtczuk <rafal at invisiblethingslab dot com>
| Marek Marczykowski <marmarek at invisiblethingslab dot com>
