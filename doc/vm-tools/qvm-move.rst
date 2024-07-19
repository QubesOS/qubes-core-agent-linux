===========
qvm-move(1)
===========

NAME
====
qvm-move - move specified files to a destination VM. Prompt user to select a destination VM. Does not work in dom0.

SYNOPSIS
========
| qvm-move [--without-progress] file [file]+

OPTIONS
=======
--without-progress
    Don't display progress info


=================
qvm-move-to-vm(1)
=================
For use in scripting; for interactive use, use qvm-move.

NAME
====
qvm-move-to-vm - move specified files to specified destination VM. Deprecated outside of dom0.

SYNOPSIS
========
| qvm-move-to-vm [--without-progress] dest_vmname file [file]+

OPTIONS
=======
--without-progress
    Don't display progress info


AUTHORS
=======
| Joanna Rutkowska <joanna at invisiblethingslab dot com>
| Rafal Wojtczuk <rafal at invisiblethingslab dot com>
| Marek Marczykowski <marmarek at invisiblethingslab dot com>
