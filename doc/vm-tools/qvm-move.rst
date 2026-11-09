===========
qvm-move(1)
===========

NAME
====
qvm-move - move specified files to a destination VM. Prompt user to select a destination VM. Does not work in dom0.

SYNOPSIS
========
| qvm-move [--without-progress] [--no-conflict-dialog] file [file]+

DESCRIPTION
===========
Like qvm-copy(1), then the files are removed from this VM. If anything fails,
including when the destination VM skips a file that already exists there,
no file is removed.

OPTIONS
=======
--without-progress
    Don't display progress info

--no-conflict-dialog
    If a file already exists in the destination VM, fail instead of asking
    there what to do. Not available when some file names are only accepted
    with the qubes.Filecopy+allow-all-names service


=================
qvm-move-to-vm(1)
=================
For use in scripting; for interactive use, use qvm-move.

NAME
====
qvm-move-to-vm - move specified files to specified destination VM. Deprecated outside of dom0.

SYNOPSIS
========
| qvm-move-to-vm [--without-progress] [--no-conflict-dialog] dest_vmname file [file]+

OPTIONS
=======
--without-progress
    Don't display progress info

--no-conflict-dialog
    If a file already exists in the destination VM, fail instead of asking
    there what to do. Not available when some file names are only accepted
    with the qubes.Filecopy+allow-all-names service


AUTHORS
=======
| Joanna Rutkowska <joanna at invisiblethingslab dot com>
| Rafal Wojtczuk <rafal at invisiblethingslab dot com>
| Marek Marczykowski <marmarek at invisiblethingslab dot com>
