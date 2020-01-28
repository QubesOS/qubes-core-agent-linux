This directory (/etc/qubes/applications) is used to override parts of files in
/usr/share/applications and other applications directories.

For each desktop file there, you can create directory named after the file plus
".d", then place files there. All such files will be read (in lexicographical
order) and lines specified there will override respective entries in the
original file.

This can be used for example to override behaviour of a specific application in
particular VM type.

For example, you can extend `/usr/share/applications/firefox.desktop` by
creating `/etc/qubes/applications/firefox.desktop.d/50_user.conf` with:
```
[Desktop Entry]
Exec=firefox --private-window http://example.com %u
```

This would mean that `Exec` key would be read as your command line, regardless
of original entry in `/usr/share/applications/firefox.desktop`.
