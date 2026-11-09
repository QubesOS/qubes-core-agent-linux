===========
qvm-copy(1)
===========

NAME
====
qvm-copy - copy specified files to a destination VM. Prompt user to select a destination VM. Does not work in dom0.

SYNOPSIS
========
| qvm-copy [--without-progress] [--no-conflict-dialog] file [file]+

DESCRIPTION
===========
Files are copied to ~/QubesIncoming/<source VM name>/ in the destination VM.
If a file with the same name already exists there, the destination VM asks
whether to replace it, skip it, save it under another name, or stop copying.

OPTIONS
=======
--without-progress
    Don't display progress info

--no-conflict-dialog
    If a file already exists in the destination VM, fail instead of asking
    there whether to replace it, skip it, or save it under another name.
    Not available when some file names are only accepted with the
    qubes.Filecopy+allow-all-names service


=================
qvm-copy-to-vm(1)
=================
For use in scripting; for interactive use, use qvm-copy.

NAME
====
qvm-copy-to-vm - copy specified files to specified destination VM. Deprecated outside of dom0.

SYNOPSIS
========
| qvm-copy-to-vm [--without-progress] [--no-conflict-dialog] dest_vmname file [file]+

OPTIONS
=======
--without-progress
    Don't display progress info

--no-conflict-dialog
    If a file already exists in the destination VM, fail instead of asking
    there whether to replace it, skip it, or save it under another name.
    Not available when some file names are only accepted with the
    qubes.Filecopy+allow-all-names service


AUTHORS
=======
| Joanna Rutkowska <joanna at invisiblethingslab dot com>
| Rafal Wojtczuk <rafal at invisiblethingslab dot com>
| Marek Marczykowski <marmarek at invisiblethingslab dot com>
