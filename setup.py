# vim: fileencoding=utf-8

import setuptools

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

        entry_points={
            'console_scripts': [
                'qubes-firewall = qubesagent.firewall:main'
            ],
        }
    )
