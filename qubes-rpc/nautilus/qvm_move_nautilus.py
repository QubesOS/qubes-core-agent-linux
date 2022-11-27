import subprocess

from gi.repository import Nautilus, GObject


class MoveToAppvmItemExtension(GObject.GObject, Nautilus.MenuProvider):
    '''Move file(s) to AppVM.

    Uses the nautilus-python api to provide a context menu within Nautilus which
    will enable the user to select file(s) to to move to another AppVM
    '''
    def get_file_items(self, *args):
        '''Attaches context menu in Nautilus

        `args` will be `[files: List[Nautilus.FileInfo]]` in Nautilus 4.0 API,
        and `[window: Gtk.Widget, files: List[Nautilus.FileInfo]]` in Nautilus 3.0 API.
        '''
        files = args[-1]
        if not files:
            return

        menu_item = Nautilus.MenuItem(name='QubesMenuProvider::MoveToAppvm',
                                      label='Move To Other AppVM...',
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
        cmd.insert(0, '/usr/lib/qubes/qvm-move-to-vm.gnome')
        subprocess.call(cmd)
