import os
from subprocess import Popen

from gi.repository import Caja, GObject


class OpenInDvmItemExtension(GObject.GObject, Caja.MenuProvider):
    '''Open File(s) in DisposableVM.

    Uses the caja-python api to provide a context menu within Caja which
    will enable the user to select file(s) to to open in a disposableVM
    '''

    def get_file_items(self, window, files):
        '''Attaches context menu in Caja
        '''
        if not files:
            return

        menu_item1 = Caja.MenuItem(name='QubesMenuProvider::OpenInDvm',
                                   label='Edit in disposable qube',
                                   tip='',
                                   icon='')

        menu_item1.connect('activate', self.on_menu_item_clicked, files)

        menu_item2 = Caja.MenuItem(name='QubesMenuProvider::ViewInDvm',
                                   label='View in disposable qube',
                                   tip='',
                                   icon='')

        menu_item2.connect('activate',
                self.on_menu_item_clicked,
                files, True)
        return menu_item1, menu_item2,

    def on_menu_item_clicked(self, menu, files, view_only=False):
        '''Called when user chooses files though Caja context menu.
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
