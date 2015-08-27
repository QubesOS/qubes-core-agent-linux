This directory (/etc/qubes/autostart) is used to override parts of files in
/etc/xdg/autostart. For each desktop file there, you can create directory named
after the file plus ".d", then place files there. All such files will be read
(in lexicographical order) and lines specified there will override respective
entries in the original file. This can be used for example to enable or disable
specific application in particular VM type.

For example, you can extend `/etc/xdg/autostart/gnome-keyring-ssh.desktop` by
creating `/etc/qubes/autostart/gnome-keyring-ssh.desktop.d/50_user.conf` with:
```
[Desktop Entry]
OnlyShowIn=X-AppVM;
```

This would mean that `OnlyShowIn` key would be read as `X-AppVM;`, regardless
of original entry in `/etc/xdg/autostart/gnome-keyring-ssh.desktop`.

This mechanism overrides only content of /etc/xdg/autostart, files placed in
~/.config/autostart are unaffected, so can be used to override settings per-VM
basis.
