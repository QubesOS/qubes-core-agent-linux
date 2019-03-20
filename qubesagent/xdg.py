import functools

from gi.repository import Gio  # pylint: disable=import-error
from gi.repository import GLib  # pylint: disable=import-error
import sys
import os

def pid_callback(launcher, pid, pid_list):
    pid_list.append(pid)

def dbus_name_change(loop, name, old_owner, new_owner):
    if not new_owner:
        loop.quit()

def launch(desktop, *files, **kwargs):
    wait = kwargs.pop('wait', True)
    launcher = Gio.DesktopAppInfo.new_from_filename(desktop)
    try:
        import dbus
        from dbus.mainloop.glib import DBusGMainLoop
        if hasattr(launcher, 'get_boolean'):
            activatable = launcher.get_boolean('DBusActivatable')
            if activatable:
                loop = GLib.MainLoop()
                DBusGMainLoop(set_as_default=True)
                bus = dbus.SessionBus()
                service_id = launcher.get_id()
                # cut the .desktop suffix
                service_id = service_id[:-len('.desktop')]
                # see D-Bus Activation Desktop entry specification
                object_path = '/' + service_id.replace('.', '/').\
                    replace('-', '_')
                try:
                    proxy = bus.get_object(service_id, object_path)
                    match = bus.add_signal_receiver(
                        functools.partial(dbus_name_change, loop),
                        'NameOwnerChanged',
                        dbus.BUS_DAEMON_IFACE,
                        dbus.BUS_DAEMON_NAME,
                        dbus.BUS_DAEMON_PATH)
                    if files:
                        proxy.Open(files, {},
                            dbus_interface='org.freedesktop.Application')
                    else:
                        proxy.Activate({},
                            dbus_interface='org.freedesktop.Application')
                except dbus.DBusException as e:
                    print(e)
                    # fallback to non-dbus version
                    pass
                else:
                    if wait:
                        loop.run()
                    match.remove()
                    return
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
