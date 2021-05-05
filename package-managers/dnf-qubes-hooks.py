# coding=utf-8
#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2015  Marek Marczykowski-Górecki
#                                <marmarek@invisiblethingslab.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import absolute_import
from distutils.version import LooseVersion
import logging
import dnf
import dnf.const
import subprocess

PLUGIN_CONF = 'qubes-hooks'

def is_active(service):
    status = subprocess.call(["systemctl", "is-active", "--quiet", service])
    return status == 0

class QubesHooks(dnf.Plugin):
    name = 'qubes-hooks'

    def __init__(self, base, cli):
        super(QubesHooks, self).__init__(base, cli)
        self.base = base
        self.log = logging.getLogger('dnf')

    def resolved(self):
        if not is_active("qubes-qrexec-agent"):
            return
        # in case of no action to do, transaction() hook won't be called;
        # report updates availability here - especially when everything is up
        # to date - to clear updates-available flag
        if not self.base.transaction:
            query = self.base.sack.query()
            query = query.upgrades()
            updates = set(query.run())
            subprocess.call([
                '/usr/lib/qubes/qrexec-client-vm',
                'dom0',
                'qubes.NotifyUpdates',
                '/bin/echo',
                str(len(updates))
            ])

    def transaction(self):
        if not is_active("qubes-qrexec-agent"):
            return
        if LooseVersion(dnf.const.VERSION) < '2.0.0':
            config = self.read_config(self.base.conf, PLUGIN_CONF)
        else:
            config = self.read_config(self.base.conf)

        if config.getboolean('main', 'notify-updates'):
            # Get all updates available _before_ this transaction
            query = self.base.sack.query()
            query = query.upgrades()
            updates = set(query.run())
            # Get packages installed in this transaction...
            just_installed = self.base.transaction
            # ...and filter them out of available updates
            for item in just_installed:
                updates.discard(item.pkg)
            subprocess.call([
                '/usr/lib/qubes/qrexec-client-vm',
                'dom0',
                'qubes.NotifyUpdates',
                '/bin/echo',
                str(len(updates))
            ])

        self.log.info("Notifying dom0 about installed applications")
        subprocess.call(['/etc/qubes-rpc/qubes.PostInstall'])
