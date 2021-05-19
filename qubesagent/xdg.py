import functools

from gi.repository import Gio  # pylint: disable=import-error
from gi.repository import GLib  # pylint: disable=import-error
import sys
import os

def pid_callback(launcher, pid, data):
    pid_list, loop = data
    pid_list.append(pid)
    GLib.child_watch_add(0, pid, lambda *args: loop.quit())

def dbus_name_change(loop, service_id, name, old_owner, new_owner):
    if name != service_id:
        return
    if not new_owner:
        loop.quit()

def launch(desktop, *files, **kwargs):
    wait = kwargs.pop('wait', True)
    launcher = Gio.DesktopAppInfo.new_from_filename(desktop)
    loop = None
    try:
        import dbus
        from dbus.mainloop.glib import DBusGMainLoop
        loop = GLib.MainLoop()
        DBusGMainLoop(set_as_default=True)
        if hasattr(launcher, 'get_boolean'):
            activatable = launcher.get_boolean('DBusActivatable')
            if activatable:
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
                        functools.partial(dbus_name_change, loop, service_id),
                        'NameOwnerChanged')
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
        if loop is None:
            loop = GLib.MainLoop()
        pid_list = []
        flags = GLib.SpawnFlags.SEARCH_PATH | GLib.SpawnFlags.DO_NOT_REAP_CHILD
        launcher.launch_uris_as_manager(files, None, flags, None, None,
                pid_callback, (pid_list, loop))
        
        if pid_list:
            # run the loop only if there is some PID watcher registered -
            # otherwise nothing will stop it ever
            loop.run()
    else:
        launcher.launch(files, None)

if __name__ == "__main__":
    launch(*sys.argv[1:])
