# If the app-dispvm service is enabled, open many file formats in a DispVM
# automatically
if [ "$(qubesdb-read /qubes-service/app-dispvm)" -eq 1 ]
then
    XDG_DATA_DIRS="/usr/share/qubes/xdg-override:$XDG_DATA_DIRS"
fi

