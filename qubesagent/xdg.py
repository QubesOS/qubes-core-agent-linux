from gi.repository import Gio  # pylint: disable=import-error
from gi.repository import GLib  # pylint: disable=import-error
import sys
import os

def pid_callback(launcher, pid, pid_list):
    pid_list.append(pid)

def launch(desktop, *files, **kwargs):
    wait = kwargs.pop('wait', True)
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
    except ImportError:
        pass
    if wait:
        pid_list = []
        flags = GLib.SpawnFlags.SEARCH_PATH | GLib.SpawnFlags.DO_NOT_REAP_CHILD
        launcher.launch_uris_as_manager(files, None, flags, None, None,
                pid_callback, pid_list)
        for pid in pid_list:
            os.waitpid(pid, 0)
    else:
        launcher.launch(files, None)

if __name__ == "__main__":
    launch(*sys.argv[1:])
