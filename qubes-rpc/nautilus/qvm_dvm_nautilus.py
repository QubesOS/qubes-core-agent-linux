import os.path
from gi.repository import Nautilus, GObject, GLib, Gio


class OpenInDvmItemExtension(GObject.GObject, Nautilus.MenuProvider):
    '''Open File(s) in DisposableVM.

    Uses the nautilus-python api to provide a context menu within Nautilus which
    will enable the user to select file(s) to to open in a disposableVM
    '''

    def get_file_items(self, *args):
        '''Attaches context menu in Nautilus

        `args` will be `[files: List[Nautilus.FileInfo]]` in Nautilus 4.0 API,
        and `[window: Gtk.Widget, files: List[Nautilus.FileInfo]]` in Nautilus 3.0 API.
        '''
        files = args[-1]
        if not files:
            return

        menu_item1 = Nautilus.MenuItem(name='QubesMenuProvider::OpenInDvm',
                                      label='Edit in disposable qube',
                                      tip='',
                                      icon='')

        menu_item1.connect('activate', self.on_menu_item_clicked, files)

        menu_item2 = Nautilus.MenuItem(name='QubesMenuProvider::ViewInDvm',
                                      label='View in disposable qube',
                                      tip='',
                                      icon='')

        menu_item2.connect('activate',
                self.on_menu_item_clicked,
                files, True)
        return menu_item1, menu_item2,

    def on_menu_item_clicked(self, menu, files, view_only=False):
        '''Called when user chooses files though Nautilus context menu.
        '''
        for file_obj in files:
            file_location = file_obj.get_location()
            file_uri = file_location.get_uri()
            if file_uri.startswith('file:///'):
                if not file_obj.is_gone():
                    # Check if file still exists
                    file_path = file_location.get_path()
                else:
                    return
            elif file_uri.startswith('recent:///'):
                try:
                    file_info = file_location.query_info(
                            Gio.FILE_ATTRIBUTE_STANDARD_TARGET_URI, 0, None)
                    target_uri = file_info.get_attribute_string(
                            Gio.FILE_ATTRIBUTE_STANDARD_TARGET_URI)
                    if target_uri.startswith('file://'):
                        file_path = target_uri[7:]
                    if not os.path.exists(file_path):
                        return
                except GLib.GError:
                    #TODO: Decide what to do if the recent item does not exist
                    return
            else:
                # TODO: Decide what to do with other weird URIs (eg. smb:///)
                return

            command = ['/usr/bin/qvm-open-in-dvm']
            if view_only:
                command.append('--view-only')
            command.append(file_path)

            pid = GLib.spawn_async(command)[0]
            GLib.spawn_close_pid(pid)
