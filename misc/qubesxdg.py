#!/usr/bin/python

from gi.repository import Gio
import sys
import dbus

def launch(desktop, *files):
    launcher = Gio.DesktopAppInfo.new_from_filename(desktop)
    if hasattr(launcher, 'get_boolean'):
        activatable = launcher.get_boolean('DBusActivatable')
        if activatable:
            bus = dbus.SessionBus()
            service_id = launcher.get_id()
            # cut the .desktop suffix
            service_id = service_id[:-8]
            bus.start_service_by_name(service_id)
    launcher.launch(files, None)

if __name__ == "__main__":
    launch(*sys.argv[1:])
