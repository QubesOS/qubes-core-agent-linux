import os
from subprocess import Popen

from gi.repository import Nautilus, GObject


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
                                      label='Edit In DisposableVM',
                                      tip='',
                                      icon='')

        menu_item1.connect('activate', self.on_menu_item_clicked, files)

        menu_item2 = Nautilus.MenuItem(name='QubesMenuProvider::ViewInDvm',
                                      label='View In DisposableVM',
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

            # Check if file still exists
            if file_obj.is_gone():
                return

            gio_file = file_obj.get_location()

            # Use subprocess.DEVNULL in python >= 3.3
            devnull = open(os.devnull, 'wb')
            command = ['nohup', '/usr/bin/qvm-open-in-dvm']
            if view_only:
                command.append('--view-only')
            command.append(gio_file.get_path())

            # Use Popen instead of subprocess.call to spawn the process
            Popen(command, stdout=devnull, stderr=devnull)
            devnull.close()
