from gi.repository import Nautilus, GObject, GLib


class CopyToAppvmItemExtension(GObject.GObject, Nautilus.MenuProvider):
    '''Copy file(s) to AppVM.

    Uses the nautilus-python api to provide a context menu with Nautilus which
    will enable the user to select file(s) to to copy to another AppVM
    '''
    def get_file_items(self, *args):
        '''Attaches context menu in Nautilus

        `args` will be `[files: List[Nautilus.FileInfo]]` in Nautilus 4.0 API,
        and `[window: Gtk.Widget, files: List[Nautilus.FileInfo]]` in Nautilus 3.0 API.
        '''
        files = args[-1]
        if not files:
            return

        menu_item = Nautilus.MenuItem(name='QubesMenuProvider::CopyToAppvm',
                                      label='Copy to other qube...',
                                      tip='',
                                      icon='')

        menu_item.connect('activate', self.on_menu_item_clicked, files)
        return menu_item,

    def on_menu_item_clicked(self, menu, files):
        '''Called when user chooses files though Nautilus context menu.
        '''
        paths = []
        for file_obj in files:
            file_location = file_obj.get_location()
            file_uri = file_location.get_uri()
            if file_uri.startswith('file:///'):
                if not file_obj.is_gone():
                    # Check if file is not gone
                    paths.append(file_location.get_path())
            elif file_uri.startswith('recent:///'):
                try:
                    file_info = file_location.query_info(
                            Gio.FILE_ATTRIBUTE_STANDARD_TARGET_URI, 0, None)
                    target_uri = file_info.get_attribute_string(
                            Gio.FILE_ATTRIBUTE_STANDARD_TARGET_URI)
                    if target_uri.startswith('file://'):
                        paths.append(target_uri[7:])
                except GLib.GError:
                    # TODO: Decide what to do if the recent item does not exist
                    pass
            else:
                # TODO: Decide what to do with other weird URIs (eg. smb:///)
                pass
        # Double-check if the file is not gone in the meantime
        cmd = [path for path in paths if os.path.exists(path)]
        cmd.insert(0, '/usr/lib/qubes/qvm-copy-to-vm.gnome')
        pid = GLib.spawn_async(cmd)[0]
        GLib.spawn_close_pid(pid)
