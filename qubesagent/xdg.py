import functools

from gi.repository import Gio  # pylint: disable=import-error
from gi.repository import GLib  # pylint: disable=import-error
import sys
import os
import io
from xdg.DesktopEntry import DesktopEntry


DROPINS_DIR = '/etc/qubes/applications'


def find_dropins(filename, dropins_dir):
    result = []
    app_dropins_dir = os.path.join(
        dropins_dir,
        os.path.basename(filename) + '.d')
    if os.path.isdir(app_dropins_dir):
        for dropin in sorted(os.listdir(app_dropins_dir)):
            result.append(
                os.path.join(app_dropins_dir, dropin))
    return result


def load_desktop_entry_with_dropins(filename, dropins):
    desktop_entry = DesktopEntry(filename)
    for dropin in dropins:
        dropin_entry = DesktopEntry(dropin)
        for group_name, group in dropin_entry.content.items():
            desktop_entry.content.setdefault(group_name, {}).update(group)
    return desktop_entry


def make_launcher(filename, dropins_dir=DROPINS_DIR):
    dropins = find_dropins(filename, dropins_dir)
    if not dropins:
        return Gio.DesktopAppInfo.new_from_filename(filename)

    desktop_entry = load_desktop_entry_with_dropins(filename, dropins)

    data = GLib.Bytes(ini_to_string(desktop_entry).encode('utf-8'))
    keyfile = GLib.KeyFile()
    keyfile.load_from_bytes(data, 0)
    return Gio.DesktopAppInfo.new_from_keyfile(keyfile)


def ini_to_string(ini):
    # See IniFile.write() in xdg package.

    output = io.StringIO()
    if ini.defaultGroup:
        output.write("[%s]\n" % ini.defaultGroup)
        for (key, value) in ini.content[ini.defaultGroup].items():
            output.write("%s=%s\n" % (key, value))
        output.write("\n")
    for (name, group) in ini.content.items():
        if name != ini.defaultGroup:
            output.write("[%s]\n" % name)
            for (key, value) in group.items():
                output.write("%s=%s\n" % (key, value))
            output.write("\n")

    return output.getvalue()


def pid_callback(launcher, pid, pid_list):
    pid_list.append(pid)


def dbus_name_change(loop, service_id, name, old_owner, new_owner):
    if name != service_id:
        return
    if not new_owner:
        loop.quit()


def launch(filename, *files, **kwargs):
    wait = kwargs.pop('wait', True)
    launcher = make_launcher(filename)
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
