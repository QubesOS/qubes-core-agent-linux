import os
from subprocess import Popen

from gi.repository import Nautilus, GObject


class OpenInDvmItemExtension(GObject.GObject, Nautilus.MenuProvider):
    '''Open File(s) in DisposableVM.

    Uses the nautilus-python api to provide a context menu within Nautilus which
    will enable the user to select file(s) to to open in a disposableVM
    '''

    def get_file_items(self, window, files):
        '''Attaches context menu in Nautilus
        '''
        if not files:
            return

        menu_item = Nautilus.MenuItem(name='QubesMenuProvider::OpenInDvm',
                                      label='Open In DisposableVM',
                                      tip='',
                                      icon='')

        menu_item.connect('activate', self.on_menu_item_clicked, files)
        return menu_item,

    def on_menu_item_clicked(self, menu, files):
        '''Called when user chooses files though Nautilus context menu.
        '''
        for file_obj in files:

            # Check if file still exists
            if file_obj.is_gone():
                return

            gio_file = file_obj.get_location()

            # Use subprocess.DEVNULL in python >= 3.3
            devnull = open(os.devnull, 'wb')

            # Use Popen instead of subprocess.call to spawn the process
            Popen(['nohup', '/usr/bin/qvm-open-in-dvm', gio_file.get_path()], stdout=devnull, stderr=devnull)
