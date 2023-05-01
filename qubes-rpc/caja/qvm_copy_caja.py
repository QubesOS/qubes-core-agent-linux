import subprocess

from gi.repository import Caja, GObject


class CopyToAppvmItemExtension(GObject.GObject, Caja.MenuProvider):
    '''Copy file(s) to AppVM.

    Uses the caja-python api to provide a context menu with Caja which
    will enable the user to select file(s) to to copy to another AppVM
    '''
    def get_file_items(self, window, files):
        '''Attaches context menu in Caja
        '''
        if not files:
            return

        menu_item = Caja.MenuItem(name='QubesMenuProvider::CopyToAppvm',
                                  label='Copy to other qube...',
                                  tip='',
                                  icon='')

        menu_item.connect('activate', self.on_menu_item_clicked, files)
        return menu_item,

    def on_menu_item_clicked(self, menu, files):
        '''Called when user chooses files though Caja context menu.
        '''
        cmd = [file_obj.get_location().get_path()
               for file_obj in files
               # Check if file is not gone
               if not file_obj.is_gone()]
        cmd.insert(0, '/usr/lib/qubes/qvm-copy-to-vm.gnome')
        subprocess.call(cmd)
