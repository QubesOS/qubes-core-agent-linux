from unittest import TestCase
import tempfile
import shutil
import os

from qubesagent.xdg import find_dropins, load_desktop_entry_with_dropins, \
    ini_to_string


class TestXdg(TestCase):
    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tempdir)

    def test_00_load_desktop_entry(self):
        filename = os.path.join(self.tempdir, 'firefox.desktop')
        dropins_dir = os.path.join(self.tempdir, 'dropins')
        dropin_filename = os.path.join(
            self.tempdir, 'dropins', 'firefox.desktop.d', '030_qubes.conf')

        with open(filename, 'w') as f:
            f.write('''\
[Desktop Entry]
Name=Firefox
Exec=firefox %u
''')

        os.makedirs(os.path.dirname(dropin_filename))
        with open(dropin_filename, 'w') as f:
            f.write('''\
[Desktop Entry]
Exec=my-firefox %u

[Other Group]
X-Key=yes
''')

        dropins = find_dropins(filename, dropins_dir)
        self.assertListEqual(
            dropins,
            [dropin_filename])

        desktop_entry = load_desktop_entry_with_dropins(filename, dropins)
        self.assertEqual(desktop_entry.content['Desktop Entry']['Name'],
                         'Firefox')
        self.assertEqual(desktop_entry.content['Desktop Entry']['Exec'],
                         'my-firefox %u')
        self.assertEqual(desktop_entry.content['Other Group']['X-Key'],
                         'yes')

    def test_01_init_to_string(self):
        filename = os.path.join(self.tempdir, 'firefox.desktop')
        content = '''\
[Desktop Entry]
Name=Firefox
Exec=firefox %u

[Other Group]
X-Key=yes
'''

        with open(filename, 'w') as f:
            f.write(content)

        desktop_entry = load_desktop_entry_with_dropins(filename, [])
        output = ini_to_string(desktop_entry)
        self.assertEqual(output.rstrip(), content.rstrip())
