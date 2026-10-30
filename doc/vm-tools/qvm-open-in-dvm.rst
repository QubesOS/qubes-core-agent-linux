===============
qvm-open-in-dvm
===============

NAME
====
qvm-open-in-dvm - open files, directories or a URL in a disposable VM

SYNOPSIS
========
| qvm-open-in-dvm [--view-only] filename
| qvm-open-in-dvm URL
| qvm-open-in-dvm file|directory...

Several files, or a directory, are opened in the same disposable VM, see
qvm-open-in-vm(1).

OPTIONS
=======

--view-only
    Do not send changes back. Always the case when opening several files or a
    directory.


NOTES
=====
Typing "xdg-settings set default-web-browser qvm-open-in-dvm.desktop" will make it so that gnome-terminal can use this,
to open a URL on the terminal screen in a disposable VM. 
(by right clicking on a URL on the terminal screen, then selecting "open with" to open the link)

Typing "xdg-settings set default-web-browser firefox.desktop" will put it back to default behavior


AUTHORS
=======
| Joanna Rutkowska <joanna at invisiblethingslab dot com>
| Rafal Wojtczuk <rafal at invisiblethingslab dot com>
| Marek Marczykowski <marmarek at invisiblethingslab dot com>
