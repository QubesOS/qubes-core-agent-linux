# vim: fileencoding=utf-8

import os

import setuptools
import setuptools.command.install
import re


CONSOLE_SCRIPTS = [
    ('qubes-firewall', 'qubesagent.firewall'),
    ('qubes-vmexec', 'qubesagent.vmexec'),
]


# create simple scripts that run much faster than "console entry points"
class CustomInstall(setuptools.command.install.install):
    def run(self):
        bin = os.path.join(self.root, "usr/bin")
        try:
            os.makedirs(bin)
        except:
            pass
        for file, pkg in CONSOLE_SCRIPTS:
            path = os.path.join(bin, file)
            with open(path, "w") as f:
                f.write(
"""#!/usr/bin/python3
from {} import main
import sys
if __name__ == '__main__':
	sys.exit(main())
""".format(pkg))

            os.chmod(path, 0o755)
        setuptools.command.install.install.run(self)


if __name__ == '__main__':
    setuptools.setup(
        name='qubesagent',
        version=open('version').read().strip(),
        author='Invisible Things Lab',
        author_email='marmarek@invisiblethingslab.com',
        description='Qubes core-agent-linux package',
        license='GPL2+',
        url='https://www.qubes-os.org/',

        packages=('qubesagent',),

        cmdclass={
            'install': CustomInstall,
        },
    )
