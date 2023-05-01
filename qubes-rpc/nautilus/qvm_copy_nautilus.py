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
        cmd = [file_obj.get_location().get_path()
               for file_obj in files
               # Check if file is not gone
               if not file_obj.is_gone()]
        cmd.insert(0, '/usr/lib/qubes/qvm-copy-to-vm.gnome')
        pid = GLib.spawn_async(cmd)[0]
        GLib.spawn_close_pid(pid)
