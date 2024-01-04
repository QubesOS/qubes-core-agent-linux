==============
qvm-copy
==============

NAME
====
qvm-copy - copy specified files to a destination VM. Prompt user to select a destination VM. Does not work in dom0.

SYNOPSIS
========
| qvm-copy [--without-progress] file [file]+

OPTIONS
=======
--without-progress
    Don't display progress info


==============
qvm-copy-to-vm
==============
For use in scripting; for interactive use, use qvm-copy.

NAME
====
qvm-copy-to-vm - copy specified files to specified destination VM. Deprecated outside of dom0.

SYNOPSIS
========
| qvm-copy-to-vm [--without-progress] dest_vmname file [file]+

OPTIONS
=======
--without-progress
    Don't display progress info


AUTHORS
=======
| Joanna Rutkowska <joanna at invisiblethingslab dot com>
| Rafal Wojtczuk <rafal at invisiblethingslab dot com>
| Marek Marczykowski <marmarek at invisiblethingslab dot com>
