#!/usr/bin/python

from gi.repository import Gio
import sys

def launch(desktop, *files):
    launcher = Gio.DesktopAppInfo.new_from_filename(desktop)
    try:
        import dbus
        if hasattr(launcher, 'get_boolean'):
            activatable = launcher.get_boolean('DBusActivatable')
            if activatable:
                bus = dbus.SessionBus()
                service_id = launcher.get_id()
                # cut the .desktop suffix
                service_id = service_id[:-8]
                try:
                    bus.start_service_by_name(service_id)
                except dbus.DBusException:
                    pass
        return launcher.launch(files, None)
    except ImportError:
        pass
    launcher.launch(files, None)

if __name__ == "__main__":
    launch(*sys.argv[1:])
