#!/usr/bin/python2 -O
# vim: fileencoding=utf-8

#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2016
#                   Marek Marczykowski-Górecki <marmarek@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
import logging
import os
import socket
import subprocess
from distutils import spawn

import daemon

import qubesdb
import sys

import signal


class RuleParseError(Exception):
    pass


class RuleApplyError(Exception):
    pass


class FirewallWorker(object):
    def __init__(self):
        self.terminate_requested = False
        self.qdb = qubesdb.QubesDB()
        self.log = logging.getLogger('qubes.firewall')
        self.log.addHandler(logging.StreamHandler(sys.stderr))

    def init(self):
        '''Create appropriate chains/tables'''
        raise NotImplementedError

    def cleanup(self):
        '''Remove tables/chains - reverse work done by init'''
        raise NotImplementedError

    def apply_rules(self, source_addr, rules):
        '''Apply rules in given source address'''
        raise NotImplementedError

    def read_rules(self, target):
        '''Read rules from QubesDB and return them as a list of dicts'''
        entries = self.qdb.multiread('/qubes-firewall/{}/'.format(target))
        assert isinstance(entries, dict)
        # drop full path
        entries = dict(((k.split('/')[3], v) for k, v in entries.items()))
        if 'policy' not in entries:
            raise RuleParseError('No \'policy\' defined')
        policy = entries.pop('policy')
        rules = []
        for ruleno, rule in sorted(entries.items()):
            if len(ruleno) != 4 or not ruleno.isdigit():
                raise RuleParseError(
                    'Unexpected non-rule found: {}={}'.format(ruleno, rule))
            rule_dict = dict(elem.split('=') for elem in rule.split(' '))
            if 'action' not in rule_dict:
                raise RuleParseError('Rule \'{}\' lack action'.format(rule))
            rules.append(rule_dict)
        rules.append({'action': policy})
        return rules

    def list_targets(self):
        return set(t.split('/')[2] for t in self.qdb.list('/qubes-firewall/'))

    @staticmethod
    def is_ip6(addr):
        return addr.count(':') > 0

    def log_error(self, msg):
        self.log.error(msg)
        subprocess.call(
            ['notify-send', '-t', '3000', msg],
            env=os.environ.copy().update({'DISPLAY': ':0'})
        )

    def handle_addr(self, addr):
        try:
            rules = self.read_rules(addr)
            self.apply_rules(addr, rules)
        except RuleParseError as e:
            self.log_error(
                'Failed to parse rules for {} ({}), blocking traffic'.format(
                    addr, str(e)
                ))
            self.apply_rules(addr, [{'action': 'drop'}])
        except RuleApplyError as e:
            self.log_error(
                'Failed to apply rules for {} ({}), blocking traffic'.format(
                    addr, str(e))
            )
            # retry with fallback rules
            try:
                self.apply_rules(addr, [{'action': 'drop'}])
            except RuleApplyError:
                self.log_error(
                    'Failed to block traffic for {}'.format(addr))

    @staticmethod
    def dns_addresses(family=None):
        with open('/etc/resolv.conf') as resolv:
            for line in resolv.readlines():
                line = line.strip()
                if line.startswith('nameserver'):
                    if line.count('.') == 3 and (family or 4) == 4:
                        yield line.split(' ')[1]
                    elif line.count(':') and (family or 6) == 6:
                        yield line.split(' ')[1]

    def main(self):
        self.terminate_requested = False
        self.init()
        # initial load
        for source_addr in self.list_targets():
            self.handle_addr(source_addr)
        self.qdb.watch('/qubes-firewall/')
        try:
            for watch_path in iter(self.qdb.read_watch, None):
                # ignore writing rules itself - wait for final write at
                # source_addr level empty write (/qubes-firewall/SOURCE_ADDR)
                if watch_path.count('/') > 2:
                    continue
                source_addr = watch_path.split('/')[2]
                self.handle_addr(source_addr)
        except OSError:  # EINTR
            # signal received, don't continue the loop
            pass

        self.cleanup()

    def terminate(self):
        self.terminate_requested = True


class IptablesWorker(FirewallWorker):
    supported_rule_opts = ['action', 'proto', 'dst4', 'dst6', 'dsthost',
        'dstports', 'specialtarget', 'icmptype']

    def __init__(self):
        super(IptablesWorker, self).__init__()
        self.chains = {
            4: set(),
            6: set(),
        }

    @staticmethod
    def chain_for_addr(addr):
        '''Generate iptables chain name for given source address address'''
        return 'qbs-' + addr.replace('.', '-').replace(':', '-')

    def run_ipt(self, family, args, **kwargs):
        # pylint: disable=no-self-use
        if family == 6:
            subprocess.check_call(['ip6tables'] + args, **kwargs)
        else:
            subprocess.check_call(['iptables'] + args, **kwargs)

    def run_ipt_restore(self, family, args):
        # pylint: disable=no-self-use
        if family == 6:
            return subprocess.Popen(['ip6tables-restore'] + args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
        else:
            return subprocess.Popen(['iptables-restore'] + args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)

    def create_chain(self, addr, chain, family):
        '''
        Create iptables chain and hook traffic coming from `addr` to it.

        :param addr: source IP from which traffic should be handled by the
        chain
        :param chain: name of the chain to create
        :param family: address family (4 or 6)
        :return: None
        '''

        self.run_ipt(family, ['-N', chain])
        self.run_ipt(family,
            ['-A', 'QBS-FORWARD', '-s', addr, '-j', chain])
        self.chains[family].add(chain)

    def prepare_rules(self, chain, rules, family):
        '''
        Helper function to translate rules list into input for iptables-restore

        :param chain: name of the chain to put rules into
        :param rules: list of rules
        :param family: address family (4 or 6)
        :return: input for iptables-restore
        :rtype: str
        '''

        iptables = "*filter\n"

        fullmask = '/128' if family == 6 else '/32'

        dns = list(addr + fullmask for addr in self.dns_addresses(family))

        for rule in rules:
            unsupported_opts = set(rule.keys()).difference(
                set(self.supported_rule_opts))
            if unsupported_opts:
                raise RuleParseError(
                    'Unsupported rule option(s): {!s}'.format(unsupported_opts))
            if 'dst4' in rule and family == 6:
                raise RuleParseError('IPv4 rule found for IPv6 address')
            if 'dst6' in rule and family == 4:
                raise RuleParseError('dst6 rule found for IPv4 address')

            if 'proto' in rule:
                protos = [rule['proto']]
            else:
                protos = None

            if 'dst4' in rule:
                dsthosts = [rule['dst4']]
            elif 'dst6' in rule:
                dsthosts = [rule['dst6']]
            elif 'dsthost' in rule:
                addrinfo = socket.getaddrinfo(rule['dsthost'], None,
                    (socket.AF_INET6 if family == 6 else socket.AF_INET))
                dsthosts = set(item[4][0] + fullmask for item in addrinfo)
            else:
                dsthosts = None

            if 'dstports' in rule:
                dstports = rule['dstports'].replace('-', ':')
            else:
                dstports = None

            if rule.get('specialtarget', None) == 'dns':
                if dstports not in ('53:53', None):
                    continue
                else:
                    dstports = '53:53'
                if not dns:
                    continue
                if protos is not None:
                    protos = {'tcp', 'udp'}.intersection(protos)
                else:
                    protos = {'tcp', 'udp'}

                if dsthosts is not None:
                    dsthosts = set(dns).intersection(dsthosts)
                else:
                    dsthosts = dns

            if 'icmptype' in rule:
                icmptype = rule['icmptype']
            else:
                icmptype = None

            # make them iterable
            if protos is None:
                protos = [None]
            if dsthosts is None:
                dsthosts = [None]

            # sorting here is only to ease writing tests
            for proto in sorted(protos):
                for dsthost in sorted(dsthosts):
                    ipt_rule = '-A {}'.format(chain)
                    if dsthost is not None:
                        ipt_rule += ' -d {}'.format(dsthost)
                    if proto is not None:
                        ipt_rule += ' -p {}'.format(proto)
                    if dstports is not None:
                        ipt_rule += ' --dport {}'.format(dstports)
                    if icmptype is not None:
                        ipt_rule += ' --icmp-type {}'.format(icmptype)
                    ipt_rule += ' -j {}\n'.format(
                        str(rule['action']).upper())
                    iptables += ipt_rule

        iptables += 'COMMIT\n'
        return iptables

    def apply_rules_family(self, source, rules, family):
        '''
        Apply rules for given source address.
        Handle only rules for given address family (IPv4 or IPv6).

        :param source: source address
        :param rules: rules list
        :param family: address family, either 4 or 6
        :return: None
        '''

        chain = self.chain_for_addr(source)
        if chain not in self.chains[family]:
            self.create_chain(source, chain, family)

        iptables = self.prepare_rules(chain, rules, family)
        try:
            self.run_ipt(family, ['-F', chain])
            p = self.run_ipt_restore(family, ['-n'])
            (output, _) = p.communicate(iptables)
            if p.returncode != 0:
                raise RuleApplyError(
                    'iptables-restore failed: {}'.format(output))
        except subprocess.CalledProcessError as e:
            raise RuleApplyError('\'iptables -F {}\' failed: {}'.format(
                chain, e.output))

    def apply_rules(self, source, rules):
        if self.is_ip6(source):
            self.apply_rules_family(source, rules, 6)
        else:
            self.apply_rules_family(source, rules, 4)

    def init(self):
        # make sure 'QBS_FORWARD' chain exists - should be created before
        # starting qubes-firewall
        try:
            self.run_ipt(4, ['-nL', 'QBS-FORWARD'])
            self.run_ipt(6, ['-nL', 'QBS-FORWARD'])
        except subprocess.CalledProcessError:
            self.log_error('\'QBS-FORWARD\' chain not found, create it first')
            sys.exit(1)

    def cleanup(self):
        for family in (4, 6):
            self.run_ipt(family, ['-F', 'QBS-FORWARD'])
            for chain in self.chains[family]:
                self.run_ipt(family, ['-F', chain])
                self.run_ipt(family, ['-X', chain])


class NftablesWorker(FirewallWorker):
    supported_rule_opts = ['action', 'proto', 'dst4', 'dst6', 'dsthost',
        'dstports', 'specialtarget', 'icmptype']

    def __init__(self):
        super(NftablesWorker, self).__init__()
        self.chains = {
            4: set(),
            6: set(),
        }

    @staticmethod
    def chain_for_addr(addr):
        '''Generate iptables chain name for given source address address'''
        return 'qbs-' + addr.replace('.', '-').replace(':', '-')

    def run_nft(self, nft_input):
        # pylint: disable=no-self-use
        p = subprocess.Popen(['nft', '-f', '/dev/stdin'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        stdout, _ = p.communicate(nft_input)
        if p.returncode != 0:
            raise RuleApplyError('nft failed: {}'.format(stdout))

    def create_chain(self, addr, chain, family):
        '''
        Create iptables chain and hook traffic coming from `addr` to it.

        :param addr: source IP from which traffic should be handled by the
        chain
        :param chain: name of the chain to create
        :param family: address family (4 or 6)
        :return: None
        '''
        nft_input = (
            'table {family} {table} {{\n'
            '  chain {chain} {{\n'
            '  }}\n'
            '  chain forward {{\n'
            '    {family} saddr {ip} jump {chain}\n'
            '  }}\n'
            '}}\n'.format(
                family=("ip6" if family == 6 else "ip"),
                table='qubes-firewall',
                chain=chain,
                ip=addr,
            )
        )
        self.run_nft(nft_input)
        self.chains[family].add(chain)

    def prepare_rules(self, chain, rules, family):
        '''
        Helper function to translate rules list into input for iptables-restore

        :param chain: name of the chain to put rules into
        :param rules: list of rules
        :param family: address family (4 or 6)
        :return: input for iptables-restore
        :rtype: str
        '''

        assert family in (4, 6)
        nft_rules = []
        ip_match = 'ip6' if family == 6 else 'ip'

        fullmask = '/128' if family == 6 else '/32'

        dns = list(addr + fullmask for addr in self.dns_addresses(family))

        for rule in rules:
            unsupported_opts = set(rule.keys()).difference(
                set(self.supported_rule_opts))
            if unsupported_opts:
                raise RuleParseError(
                    'Unsupported rule option(s): {!s}'.format(unsupported_opts))
            if 'dst4' in rule and family == 6:
                raise RuleParseError('IPv4 rule found for IPv6 address')
            if 'dst6' in rule and family == 4:
                raise RuleParseError('dst6 rule found for IPv4 address')

            nft_rule = ""

            if 'proto' in rule:
                if family == 4:
                    nft_rule += ' ip protocol {}'.format(rule['proto'])
                elif family == 6:
                    proto = 'icmpv6' if rule['proto'] == 'icmp' \
                        else rule['proto']
                    nft_rule += ' ip6 nexthdr {}'.format(proto)


            if 'dst4' in rule:
                nft_rule += ' ip daddr {}'.format(rule['dst4'])
            elif 'dst6' in rule:
                nft_rule += ' ip6 daddr {}'.format(rule['dst6'])
            elif 'dsthost' in rule:
                addrinfo = socket.getaddrinfo(rule['dsthost'], None,
                    (socket.AF_INET6 if family == 6 else socket.AF_INET))
                nft_rule += ' {} daddr {{ {} }}'.format(ip_match,
                    ', '.join(set(item[4][0] + fullmask for item in addrinfo)))

            if 'dstports' in rule:
                dstports = rule['dstports']
                if len(set(dstports.split('-'))) == 1:
                    dstports = dstports.split('-')[0]
            else:
                dstports = None

            if rule.get('specialtarget', None) == 'dns':
                if dstports not in ('53', None):
                    continue
                else:
                    dstports = '53'
                if not dns:
                    continue
                nft_rule += ' {} daddr {{ {} }}'.format(ip_match, ', '.join(
                    dns))

            if 'icmptype' in rule:
                if family == 4:
                    nft_rule += ' icmp type {}'.format(rule['icmptype'])
                elif family == 6:
                    nft_rule += ' icmpv6 type {}'.format(rule['icmptype'])

            # now duplicate rules for tcp/udp if needed
            # it isn't possible to specify "tcp dport xx || udp dport xx" in
            # one rule
            if dstports is not None:
                if 'proto' not in rule:
                    nft_rules.append(
                        nft_rule + ' tcp dport {} {}'.format(
                            dstports, rule['action']))
                    nft_rules.append(
                        nft_rule + ' udp dport {} {}'.format(
                            dstports, rule['action']))
                else:
                    nft_rules.append(
                        nft_rule + ' {} dport {} {}'.format(
                            rule['proto'], dstports, rule['action']))
            else:
                nft_rules.append(nft_rule + ' ' + rule['action'])

        return (
            'flush chain {family} {table} {chain}\n'
            'table {family} {table} {{\n'
            '  chain {chain} {{\n'
            '   {rules}\n'
            '  }}\n'
            '}}\n'.format(
                family=('ip6' if family == 6 else 'ip'),
                table='qubes-firewall',
                chain=chain,
                rules='\n   '.join(nft_rules)
            ))

    def apply_rules_family(self, source, rules, family):
        '''
        Apply rules for given source address.
        Handle only rules for given address family (IPv4 or IPv6).

        :param source: source address
        :param rules: rules list
        :param family: address family, either 4 or 6
        :return: None
        '''

        chain = self.chain_for_addr(source)
        if chain not in self.chains[family]:
            self.create_chain(source, chain, family)

        self.run_nft(self.prepare_rules(chain, rules, family))

    def apply_rules(self, source, rules):
        if self.is_ip6(source):
            self.apply_rules_family(source, rules, 6)
        else:
            self.apply_rules_family(source, rules, 4)

    def init(self):
        # make sure 'QBS_FORWARD' chain exists - should be created before
        # starting qubes-firewall
        nft_init = (
            'table {family} qubes-firewall {{\n'
            '  chain forward {{\n'
            '    type filter hook forward priority 0;\n'
            '  }}\n'
            '}}\n'
        )
        nft_init = ''.join(
            nft_init.format(family=family) for family in ('ip', 'ip6'))
        self.run_nft(nft_init)

    def cleanup(self):
        nft_cleanup = (
            'delete table ip qubes-firewall\n'
            'delete table ip6 qubes-firewall\n'
        )
        self.run_nft(nft_cleanup)


def main():
    if spawn.find_executable('nft'):
        worker = NftablesWorker()
    else:
        worker = IptablesWorker()
    context = daemon.DaemonContext()
    context.stderr = sys.stderr
    context.detach_process = False
    context.files_preserve = [worker.qdb.watch_fd()]
    context.signal_map = {
        signal.SIGTERM: lambda _signal, _stack: worker.terminate(),
    }
    with context:
        worker.main()

if __name__ == '__main__':
    main()
