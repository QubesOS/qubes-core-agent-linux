===============
qvm-open-in-dvm
===============

NAME
====
qvm-open-in-dvm - open a specified file or URL in a disposable VM

SYNOPSIS
========
| qvm-open-in-dvm filename
| qvm-open-in-dvm URL

OPTIONS
=======


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
