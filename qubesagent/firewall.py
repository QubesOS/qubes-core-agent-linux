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
import pwd
import shutil
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
        """Create appropriate chains/tables"""
        raise NotImplementedError

    def sd_notify(self, state):
        """Send notification to systemd, if available"""
        # based on sdnotify python module
        if 'NOTIFY_SOCKET' not in os.environ:
            return
        addr = os.environ['NOTIFY_SOCKET']
        if addr[0] == '@':
            addr = '\0' + addr[1:]
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.connect(addr)
            sock.sendall(state.encode())
        except:
            # generally ignore error on systemd notification
            pass

    def cleanup(self):
        """Remove tables/chains - reverse work done by init"""
        raise NotImplementedError

    def apply_rules(self, source, rules):
        if self.is_ip6(source):
            self.apply_rules_family(source, rules, 6)
        else:
            self.apply_rules_family(source, rules, 4)

    def update_connected_ips(self, family):
        raise NotImplementedError

    def get_connected_ips(self, family):
        ips = self.qdb.read('/connected-ips6' if family == 6 else '/connected-ips')
        if ips is None:
            return []
        return ips.decode().split()

    def run_firewall_dir(self):
        """Run scripts dir contents, before user script"""
        script_dir_paths = ['/etc/qubes/qubes-firewall.d',
                            '/rw/config/qubes-firewall.d']
        for script_dir_path in script_dir_paths:
            if not os.path.isdir(script_dir_path):
                continue
            for d_script in sorted(os.listdir(script_dir_path)):
                d_script_path = os.path.join(script_dir_path, d_script)
                if os.path.isfile(d_script_path) and \
                        os.access(d_script_path, os.X_OK):
                    subprocess.call([d_script_path])

    def run_user_script(self):
        """Run user script in /rw/config"""
        user_script_path = '/rw/config/qubes-firewall-user-script'
        if os.path.isfile(user_script_path) and \
                os.access(user_script_path, os.X_OK):
            subprocess.call([user_script_path])

    def get_phys_interfaces(self):
        phys = set()
        with open('/proc/net/route') as f:
            routes = f.readlines()[1:]
        for route in routes:
            if 'vif' not in route:
                phys.add(route.split('\t')[0])
        return phys

    def get_ip(self):
         return self.qdb.read('/qubes-ip').decode()

    def get_gateway(self):
         return self.qdb.read('/qubes-gateway').decode()

    def read_rules(self, target):
        """Read rules from QubesDB and return them as a list of dicts"""
        entries = self.qdb.multiread('/qubes-firewall/{}/'.format(target))
        assert isinstance(entries, dict)
        # drop full path
        entries = dict(((k.split('/')[3], v.decode())
                        for k, v in entries.items()))
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

    def read_forward_rules(self):
        """Read forward rules from QubesDB and return them as a list of dicts"""
        """No policy here since they already are in the forward dict, use first/last flags"""
        entries = self.qdb.multiread('/qubes-firewall-forward/')
        # filter out base empty entry
        for key in list(entries.keys()):
            if len(key.split('/')) < 5:
                del entries[key]
        assert isinstance(entries, dict)
        # drop full path but add target ip info
        entries = dict(((k.split('/')[3] + "/" + k.split('/')[4], v.decode())
                        for k, v in entries.items()))
        rules = []

        for rulename, rule in sorted(entries.items()):
            ruleno = rulename.split('/')[1]
            ruletarget = rulename.split('/')[0]
            if len(ruleno) != 4 or not ruleno.isdigit():
                raise RuleParseError(
                    'Unexpected non-rule found: {}={}'.format(ruleno, rule))
            rule_dict = dict(elem.split('=') for elem in rule.split(' '))
            if 'action' not in rule_dict:
                raise RuleParseError('Rule \'{}\' lack action'.format(rule))
            if self.is_ip6(ruletarget):
                rule_dict['dst6'] = ruletarget
            else:
                rule_dict['dst4'] = ruletarget
            if ('dst4' in rule_dict and 'src6' in rule_dict) or ('dst6' in rule_dict and 'src4' in rule_dict):
                raise RuleParseError('It is not possible to mix IPv4 and IPv6 Networking')
            rules.append(rule_dict)
        return rules

    def resolve_dns(self, fqdn, family):
        """
        Resolve the given FQDN via DNS.
        :param fqdn: FQDN
        :param family: 4 or 6 for IPv4 or IPv6
        :return: see socket.getaddrinfo()
        :raises: RuleParseError
        """
        try:
            addrinfo = socket.getaddrinfo(fqdn, None,
                (socket.AF_INET6 if family == 6 else socket.AF_INET))
        except socket.gaierror as e:
            raise RuleParseError('Failed to resolve {}: {}'.format(
                fqdn, str(e)))
        except UnicodeError as e:
            raise RuleParseError('Invalid destination {}: {}'.format(
                fqdn, str(e)))
        return addrinfo


    def update_dns_info(self, source, dns):
        """
        Write resolved DNS addresses back to QubesDB. This can be useful
        for the user or DNS applications to pin these DNS addresses to the
        IPs resolved during firewall setup.

        :param source: VM IP
        :param dns: dict: hostname -> set of IP addresses
        :return: None
        """
        #clear old info
        self.qdb.rm('/dns/{}/'.format(source))

        for host, hostaddrs in dns.items():
            self.qdb.write('/dns/{}/{}'.format(source, host), str(hostaddrs))

    def update_handled(self, addr):
        """
        Update the QubesDB count of how often the given address was handled.
        User applications may watch these paths for count increases to remain
        up to date with QubesDB changes.
        """
        cnt = self.qdb.read('/qubes-firewall-handled/{}'.format(addr))
        try:
            cnt = int(cnt)
        except (TypeError, ValueError):
            cnt = 0
        self.qdb.write('/qubes-firewall-handled/{}'.format(addr), str(cnt+1))

    def list_targets(self):
        # here is 2 because we have /qubes-firewall/<ip>
        return set(t.split('/')[2] for t in self.qdb.list('/qubes-firewall/'))

    def list_forward_targets(self):
        # here is 3 because we have /qubes-firewall-forward/<appvm>/<ip>
        return set(t.split('/')[3] for t in self.qdb.list('/qubes-firewall-forward/'))

    @staticmethod
    def is_ip6(addr):
        return addr.count(':') > 0

    def log_error(self, msg):
        self.log.error(msg)

        user = (self.qdb.read('/default-user') or b'user').decode()
        try:
            uid = pwd.getpwnam(user).pw_uid
        except KeyError:
            uid = 1000

        try:
            subprocess.check_output(
                ['runuser', '-u', user, '--', 'notify-send', '-t', '8000',
                    '--icon=network-error', msg],
                env={'DISPLAY': ':0',
                    'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                    #dbus address is needed on fedora, but optional on debian
                    'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/{}/bus'.format(
                        uid)},
                stderr=subprocess.STDOUT,
            )
        except Exception as e:
            self.log.error(
                'Failed to notify the user about: {} ({})'.format(
                    msg, str(e)
                ))

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

        self.update_handled(addr)

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
        self.run_firewall_dir()
        self.run_user_script()
        self.sd_notify('READY=1')
        self.qdb.watch('/qubes-firewall/')
        self.qdb.watch('/qubes-firewall-forward/')
        self.qdb.watch('/connected-ips')
        self.qdb.watch('/connected-ips6')
        # initial load
        for source_addr in self.list_targets():
            self.handle_addr(source_addr)

        self.load_forwarding()

        self.update_connected_ips(4)
        self.update_connected_ips(6)
        try:
            for watch_path in iter(self.qdb.read_watch, None):
                if watch_path == '/connected-ips':
                    self.update_connected_ips(4)

                if watch_path == '/connected-ips6':
                    self.update_connected_ips(6)

                # ignore writing rules itself - wait for final write at
                # source_addr level empty write (/qubes-firewall/SOURCE_ADDR)
                if watch_path.startswith('/qubes-firewall/') and watch_path.count('/') == 2:
                    source_addr = watch_path.split('/')[2]
                    self.handle_addr(source_addr)

                if watch_path.startswith('/qubes-firewall-forward/'):
                    self.load_forwarding()

        except OSError:  # EINTR
            # signal received, don't continue the loop
            pass

        self.cleanup()
        if 'qubes-firewall-forward' in self.chains[4] or 'qubes-firewall-forward' in self.chains[6]:
            self.forward_cleanup()

    def load_forwarding(self):
        try:
            rules = self.read_forward_rules()
            self.apply_forward_rules(rules)
        
        except RuleParseError as e:
            self.log_error(
                'Failed to parse forwarding rule ({})'.format(str(e))
                )
        
        except RuleApplyError as e:
            self.log_error(
                'Failed to apply forwarding rule ({})'.format(str(e))
            )

    def terminate(self):
        self.terminate_requested = True



class IptablesWorker(FirewallWorker):
    supported_rule_opts = ['action', 'proto', 'dst4', 'dst6', 'dsthost',
                           'dstports', 'specialtarget', 'icmptype']

    supported_forward_rule_opts = ['action', 'proto', 'src4', 'src6', 'dst4', 'dst6',
                           'srcports', 'dstports', 'forwardtype', 'last']

    def __init__(self):
        super(IptablesWorker, self).__init__()
        self.chains = {
            4: set(),
            6: set(),
        }

    @staticmethod
    def chain_for_addr(addr):
        """Generate iptables chain name for given source address address"""
        return 'qbs-' + addr.replace('.', '-').replace(':', '-')[-20:]

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
        """
        Create iptables chain and hook traffic coming from `addr` to it.

        :param addr: source IP from which traffic should be handled by the
        chain
        :param chain: name of the chain to create
        :param family: address family (4 or 6)
        :return: None
        """

        self.run_ipt(family, ['-N', chain])
        self.run_ipt(family,
            ['-I', 'QBS-FORWARD', '-s', addr, '-j', chain])
        self.chains[family].add(chain)

    def prepare_rules(self, chain, rules, family):
        """
        Helper function to translate rules list into input for iptables-restore

        :param chain: name of the chain to put rules into
        :param rules: list of rules
        :param family: address family (4 or 6)
        :return: tuple: (input for iptables-restore, dict of DNS records resolved
                        during execution)
        :rtype: (str, dict)
        """

        iptables = "*filter\n"

        fullmask = '/128' if family == 6 else '/32'

        dns = list(addr + fullmask for addr in self.dns_addresses(family))

        ret_dns = {}

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
                if rule['proto'] == 'icmp' and family == 6:
                    protos = ['icmpv6']
                else:
                    protos = [rule['proto']]
            else:
                protos = None

            if 'dst4' in rule:
                dsthosts = [rule['dst4']]
            elif 'dst6' in rule:
                dsthosts = [rule['dst6']]
            elif 'dsthost' in rule:
                addrinfo = self.resolve_dns(rule['dsthost'], family)
                dsthosts = set(item[4][0] + fullmask for item in addrinfo)
                ret_dns[rule['dsthost']] = dsthosts
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

            if rule['action'] == 'accept':
                action = 'ACCEPT'
            elif rule['action'] == 'drop':
                action = 'REJECT --reject-with {}'.format(
                    'icmp6-adm-prohibited' if family == 6 else
                    'icmp-admin-prohibited')
            else:
                raise RuleParseError(
                    'Invalid rule action {}'.format(rule['action']))

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
                    ipt_rule += ' -j {}\n'.format(action)
                    iptables += ipt_rule

        iptables += 'COMMIT\n'
        return (iptables, ret_dns)

    def prepare_forward_rules(self, chain, rules, family):
        """
        Helper function to translate rules list into input for iptables-restore

        :param chain: name of the chain to put rules into
        :param rules: list of rules
        :param family: address family (4 or 6)
        :return: tuple: (input for iptables-restore, dict of DNS records resolved
                        during execution)
        :rtype: (str, dict)
        """
        assert family in (4, 6)

        iptables = "*filter\n"

        fullmask = '/128' if family == 6 else '/32'

        for rule in rules:
            unsupported_opts = set(rule.keys()).difference(
                set(self.supported_forward_rule_opts))
            if unsupported_opts:
                raise RuleParseError(
                    'Unsupported forward rule option(s): {!s}'.format(unsupported_opts))
            if 'src4' in rule and family == 6:
                raise RuleParseError('dst4 rule found for IPv6 address')
            if 'src6' in rule and family == 4:
                raise RuleParseError('src6 rule found for IPv4 address')
            if 'dst4' in rule and family == 6:
                raise RuleParseError('dst4 rule found for IPv6 address')
            if 'dst6' in rule and family == 4:
                raise RuleParseError('dst6 rule found for IPv4 address')

            if 'proto' in rule:
                protos = [rule['proto']]
            else:
                protos = ['tcp', 'udp']

            if 'src4' in rule:
                srchost = [rule['src4']]
            elif 'src6' in rule:
                srchost = [rule['src6']]
            else:
                raise RuleParseError('src4/src6 is mandatory for forward rules')

            # dsthost here is added automatically in the previous functions
            # it is always a /32
            if 'dst4' in rule:
                dsthost = [rule['dst4']]
            elif 'dst6' in rule:
                dsthost = [rule['dst6']]
            else:
                dsthost = None

            if 'srcports' in rule:
                srcports = rule['srcports'].replace('-', ':')
            else:
                raise RuleParseError('srcports is mandatory for forward rules')

            # dstports cannot be a range
            # a single port can be redirected to multiple ports, but not vice versa
            if 'dstports' in rule:
                if rule['dstports'].split('-')[0] !=  rule['dstports'].split('-')[1]:
                    raise RuleParseError('dstports must be a single port')
                dstport = rule['dstports'].split('-')[0]
            else:
                raise RuleParseError('dstports is mandatory for forward rules')

            if rule['action'] != 'forward':
                raise RuleParseError(
                    'Invalid rule action {}'.format(rule['action']))

            if rule['last']:
                interfaces = self.get_phys_interfaces()
                if len(intarfaces) < 1:
                    raise RuleApplyError('There are no external interfaces available')
                for iface in sorted(interfaces):
                    for proto in sorted(protos):
                        # first rule
                        ipt_rule =  ' -t NAT'
                        ipt_rule += ' -a PREROUTING'
                        ipt_rule += ' -i {}'.format(iface)
                        if proto is not None:
                            ipt_rule += ' -p {}'.format(proto)
                        if srcports is None:
                            ipt_rule += ' --dport {}'.format(srcports)
                        ipt_rule += ' -j DNAT'
                        if dsthost is not None:
                            ipt_rule += ' --to-destination {}\n'.format(dsthost)
                        iptables += ipt_rule

                        # second rule
                        ipt_rule =  ' -I FORWARD'
                        ipt_rule += ' -i {}'.format(iface)
                        if dsthost is not None:
                            ipt_rule += ' -d {}'.format(dsthost)
                        if proto is not None:
                            ipt_rule += ' -p {}'.format(proto)
                        if srcports is None:
                            ipt_rule += ' --dport {}'.format(srcports)
                        ipt_rule += ' -m conntrack'
                        ipt_rule += ' --cstate NEW'
                        ipt_rule += ' -j ACCEPT\n'
                        iptables += ipt_rule

        iptables += 'COMMIT\n'
        return iptables

    def apply_rules_family(self, source, rules, family):
        """
        Apply rules for given source address.
        Handle only rules for given address family (IPv4 or IPv6).

        :param source: source address
        :param rules: rules list
        :param family: address family, either 4 or 6
        :return: None
        """

        chain = self.chain_for_addr(source)
        if chain not in self.chains[family]:
            self.create_chain(source, chain, family)

        (iptables, dns) = self.prepare_rules(chain, rules, family)
        try:
            self.run_ipt(family, ['-F', chain])
            p = self.run_ipt_restore(family, ['-n'])
            (output, _) = p.communicate(iptables.encode())
            if p.returncode != 0:
                raise RuleApplyError(
                    'iptables-restore failed: {}'.format(output))
            self.update_dns_info(source, dns)
        except subprocess.CalledProcessError as e:
            raise RuleApplyError('\'iptables -F {}\' failed: {}'.format(
                chain, e.output))

    def apply_forward_rules_family(self, rules, family):
        """
        Apply forward rules for given target address.
        Handle only rules for given address family (IPv4 or IPv6).

        :param source: source address
        :param rules: rules list
        :param family: address family, either 4 or 6
        :param last: whether this is the border vm or not
        :return: None
        """

        chain = self.chain_for_addr(source)
        if chain not in self.chains[family]:
            self.create_chain(source, chain, family)

        iptables = self.prepare_forward_rules(chain, rules, family)
        try:
            self.run_ipt(family, ['-F', chain])
            p = self.run_ipt_restore(family, ['-n'])
            (output, _) = p.communicate(iptables.encode())
            if p.returncode != 0:
                raise RuleApplyError(
                    'iptables-restore failed: {}'.format(output))
        except subprocess.CalledProcessError as e:
            raise RuleApplyError('\'iptables -F {}\' failed: {}'.format(
                chain, e.output))

    def update_connected_ips(self, family):
        ips = self.get_connected_ips(family)

        if not ips:
            # Just flush.
            self.run_ipt(family, ['-t', 'raw', '-F', 'QBS-PREROUTING'])
            self.run_ipt(family, ['-t', 'mangle', '-F', 'QBS-POSTROUTING'])
            return

        # Temporarily set policy to DROP while updating the rules.
        self.run_ipt(family, ['-t', 'raw', '-P', 'PREROUTING', 'DROP'])
        self.run_ipt(family, ['-t', 'mangle', '-P', 'POSTROUTING', 'DROP'])

        self.run_ipt(family, ['-t', 'raw', '-F', 'QBS-PREROUTING'])
        self.run_ipt(family, ['-t', 'mangle', '-F', 'QBS-POSTROUTING'])

        for ip in ips:
            self.run_ipt(family, [
                '-t', 'raw', '-A', 'QBS-PREROUTING',
                '!', '-i', 'vif+', '-s', ip, '-j', 'DROP'])
            self.run_ipt(family, [
                '-t', 'mangle', '-A', 'QBS-POSTROUTING',
                '!', '-o', 'vif+', '-d', ip, '-j', 'DROP'])

        self.run_ipt(family, ['-t', 'raw', '-P', 'PREROUTING', 'ACCEPT'])
        self.run_ipt(family, ['-t', 'mangle', '-P', 'POSTROUTING', 'ACCEPT'])

    def init(self):
        # Chains QBS-FORWARD, QBS-PREROUTING, QBS-POSTROUTING
        # need to be created before running this.
        try:
            self.run_ipt(4, ['-F', 'QBS-FORWARD'])
            self.run_ipt(4,
                ['-A', 'QBS-FORWARD', '!', '-i', 'vif+', '-j', 'RETURN'])
            self.run_ipt(4, ['-A', 'QBS-FORWARD', '-j', 'DROP'])
            self.run_ipt(4, ['-t', 'raw', '-F', 'QBS-PREROUTING'])
            self.run_ipt(4, ['-t', 'mangle', '-F', 'QBS-POSTROUTING'])

            self.run_ipt(6, ['-F', 'QBS-FORWARD'])
            self.run_ipt(6,
                ['-A', 'QBS-FORWARD', '!', '-i', 'vif+', '-j', 'RETURN'])
            self.run_ipt(6, ['-A', 'QBS-FORWARD', '-j', 'DROP'])
            self.run_ipt(6, ['-t', 'raw', '-F', 'QBS-PREROUTING'])
            self.run_ipt(6, ['-t', 'mangle', '-F', 'QBS-POSTROUTING'])
        except subprocess.CalledProcessError:
            self.log_error(
                'Error initializing iptables. '
                'You probably need to create QBS-FORWARD, QBS-PREROUTING and '
                'QBS-POSTROUTING chains first.'
            )
            sys.exit(1)

    def cleanup(self):
        for family in (4, 6):
            self.run_ipt(family, ['-F', 'QBS-FORWARD'])
            self.run_ipt(family, ['-t', 'raw', '-F', 'QBS-PREROUTING'])
            self.run_ipt(family, ['-t', 'mangle', '-F', 'QBS-POSTROUTING'])
            for chain in self.chains[family]:
                self.run_ipt(family, ['-F', chain])
                self.run_ipt(family, ['-X', chain])


class NftablesWorker(FirewallWorker):
    supported_rule_opts = ['action', 'proto', 'dst4', 'dst6', 'dsthost',
                           'dstports', 'specialtarget', 'icmptype']

    supported_forward_rule_opts = ['action', 'proto', 'src4', 'src6', 'dst4', 'dst6', 
                            'srcports', 'dstports', 'forwardtype', 'last']

    def __init__(self):
        super(NftablesWorker, self).__init__()
        self.chains = {
            4: set(),
            6: set(),
        }

    @staticmethod
    def chain_for_addr(addr):
        """Generate iptables chain name for given source address address"""
        return 'qbs-' + addr.replace('.', '-').replace(':', '-')

    def run_nft(self, nft_input):
        # pylint: disable=no-self-use
        p = subprocess.Popen(['nft', '-f', '/dev/stdin'],
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        stdout, _ = p.communicate(nft_input.encode())
        if p.returncode != 0:
            raise RuleApplyError('nft failed: {}'.format(stdout))

    def create_chain(self, addr, chain, family):
        """
        Create iptables chain and hook traffic coming from `addr` to it.

        :param addr: source IP from which traffic should be handled by the
        chain
        :param chain: name of the chain to create
        :param family: address family (4 or 6)
        :return: None
        """
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

    def create_forward_chain(self, family):
        """
        Create a forwarding chain using nat for forwarding rules
        """
        nft_input = (
            'table {family} qubes-firewall-forward {{\n'
            '  chain postrouting {{\n'
            '    type nat hook postrouting priority srcnat; policy accept;\n'
            '  }}\n'
            '  chain prerouting {{\n'
            '    type nat hook prerouting priority dstnat; policy accept;\n'
            '  }}\n'
            '}}\n').format(
                family=("ip6" if family == 6 else "ip")
        )
        self.run_nft(nft_input)
        self.chains[family].add('qubes-firewall-forward')

    def update_connected_ips(self, family):
        family_name = ('ip6' if family == 6 else 'ip')
        table = 'qubes-firewall'

        nft_input = (
            'flush chain {family_name} {table} prerouting\n'
            'flush chain {family_name} {table} postrouting\n'
        ).format(family_name=family_name, table=table)

        ips = self.get_connected_ips(family)
        if ips:
            addr = '{' + ', '.join(ips) + '}'
            irule = 'iifname != "vif*" {family_name} saddr {addr} drop\n'.format(
                family_name=family_name, addr=addr)
            orule = 'oifname != "vif*" {family_name} daddr {addr} drop\n'.format(
                family_name=family_name, addr=addr)

            nft_input += (
                ''
                'table {family_name} {table} {{\n'
                '  chain prerouting {{\n'
                '    {irule}'
                '  }}\n'
                '  chain postrouting {{\n'
                '    {orule}'
                '  }}\n'
                '}}\n'
            ).format(
                family_name=family_name,
                table=table,
                irule=irule,
                orule=orule,
            )

        self.run_nft(nft_input)

    def prepare_rules(self, chain, rules, family):
        """
        Helper function to translate rules list into input for nft

        :param chain: name of the chain to put rules into
        :param rules: list of rules
        :param family: address family (4 or 6)
        :return: tuple: (input for nft, dict of DNS records resolved
                        during execution)
        :rtype: (str, dict)
        """

        assert family in (4, 6)
        nft_rules = []
        ip_match = 'ip6' if family == 6 else 'ip'

        fullmask = '/128' if family == 6 else '/32'

        dns = list(addr + fullmask for addr in self.dns_addresses(family))

        ret_dns = {}

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

            if rule['action'] == 'accept':
                action = 'accept'
            elif rule['action'] == 'drop':
                action = 'reject with icmp{} type admin-prohibited'.format(
                    'v6' if family == 6 else '')
            else:
                raise RuleParseError(
                    'Invalid rule action {}'.format(rule['action']))

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
                addrinfo = self.resolve_dns(rule['dsthost'], family)
                dsthosts = set(item[4][0] + fullmask for item in addrinfo)
                nft_rule += ' {} daddr {{ {} }}'.format(ip_match,
                    ', '.join(dsthosts))
                ret_dns[rule['dsthost']] = dsthosts

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
                            dstports, action))
                    nft_rules.append(
                        nft_rule + ' udp dport {} {}'.format(
                            dstports, action))
                else:
                    nft_rules.append(
                        nft_rule + ' {} dport {} {}'.format(
                            rule['proto'], dstports, action))
            else:
                nft_rules.append(nft_rule + ' ' + action)

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
            ), ret_dns)

    def prepare_forward_rules(self, rules):
        """
        Helper function to translate rules list into input for nft

        :param chain: name of the chain to put rules into
        :param rules: list of rules
        :param family: address family (4 or 6)
        :return: tuple: (input for nft, dict of DNS records resolved
                        during execution)
        :rtype: (str, dict)
        """

        chain = 'forward'

        forward_nft_rules = []
        accept_nft_rules = []

        forward_nft_rules_6 = []
        accept_nft_rules_6 = []

        for rule in rules:
            unsupported_opts = set(rule.keys()).difference(
                set(self.supported_forward_rule_opts))
            if unsupported_opts:
                raise RuleParseError(
                    'Unsupported forward rule option(s): {!s}'.format(unsupported_opts))
            nft_rule = ""
            
            if 'proto' in rule:
                protos = [rule['proto']]
            else:
                protos = ['tcp', 'udp']

            if 'dst4' in rule:
                dstfamily = 4
                dsthost = rule['dst4']
                if self.is_ip6(dsthost):
                    raise RuleParseError(
                    'Ivalid value supplied as IPv4 address in dst4')
            elif 'dst6' in rule:
                dstfamily = 6
                dsthost = rule['dst6']
                if not self.is_ip6(dsthost):
                    raise RuleParseError(
                    'Ivalid value supplied as IPv6 address in dst6')
            else:
                raise RuleParseError(
                    'Missing dst address!')

            if 'src4' in rule:
                srcfamily = 4
                srchosts = rule['src4']
                if self.is_ip6(srchosts):
                    raise RuleParseError(
                    'Ivalid value supplied as IPv4 address in src4')
            elif 'src6' in rule:
                srcfamily = 6
                srchosts = rule['src6']
                if not self.is_ip6(srchosts):
                    raise RuleParseError(
                    'Ivalid value supplied as IPv6 address in src6')
            else:
                raise RuleParseError(
                    'Missing dst address!')

            if srcfamily != dstfamily:
                raise RuleParseError(
                    'Mixed src and dst ip version family')
            family = dstfamily

            if 'src4' in rule and family == 6:
                raise RuleParseError('dst4 rule found for IPv6 address')
            if 'src6' in rule and family == 4:
                raise RuleParseError('src6 rule found for IPv4 address')
            if 'dst4' in rule and family == 6:
                raise RuleParseError('dst4 rule found for IPv6 address')
            if 'dst6' in rule and family == 4:
                raise RuleParseError('dst6 rule found for IPv4 address')

            assert family in (4, 6)
            ip_match = 'ip6' if family == 6 else 'ip'

            fullmask = '/128' if family == 6 else '/32'

            # if the range is zero nft complains, otherwise a range is ok
            if 'srcports' in rule:
                if rule['srcports'].split('-')[0] ==  rule['srcports'].split('-')[1]:
                    srcports = rule['srcports'].split('-')[0]
                else:
                    srcports = rule['srcports']
            else:
                raise RuleParseError('srcports is mandatory for forward rules')

            # dstports cannot be a range
            # multiple ports can be redirected to a single port, but not vice versa
            if 'dstports' in rule:
                if rule['dstports'].split('-')[0] !=  rule['dstports'].split('-')[1]:
                    raise RuleParseError('dstports must be a single port')
                dstport = rule['dstports'].split('-')[0]
            else:
                raise RuleParseError('dstports is mandatory for forward rules')

            if rule['action'] != 'forward':
                raise RuleParseError(
                    'Invalid rule action {}'.format(rule['action']))

            if 'last' in rule and rule['last']:
                # is this the outside facing qubes?
                interfaces = self.get_phys_interfaces()
                if len(interfaces) < 1:
                    raise RuleApplyError('There are no external interfaces available')
                
                for iface in sorted(interfaces):
                    for proto in sorted(protos):
                        forward_entry = 'meta iifname "{iface}" {family} saddr {srchosts} {proto} dport {{ {srcports} }} dnat to {dsthost}:{dstport}'.format(iface=iface, family=ip_match, srchosts=srchosts, proto=proto, srcports=srcports, dsthost=dsthost, dstport=dstport)
                        accept_entry = 'meta iifname "{iface}" {family} daddr {dsthost} {proto} dport {dstport} ct state new counter accept'.format(iface=iface, family=ip_match, proto=proto, dsthost=dsthost, dstport=dstport)
            else:
                # internal we always use the dstport for communication between qubes. Maybe it is worth randomizing at a later stage?
                # since we removed masquerading we can retain the original srchost for filtering
                for proto in sorted(protos):
                    forward_entry = 'meta iifname "eth0" {family} saddr {srchosts} {proto} dport {{ {dstport} }} dnat to {dsthost}:{dstport}'.format(family=ip_match, srchosts=srchosts, proto=proto, dsthost=dsthost, dstport=dstport)
                    accept_entry = 'meta iifname "eth0" {family} daddr {dsthost} {proto} dport {dstport} ct state new counter accept'.format(family=ip_match, proto=proto, dsthost=dsthost, dstport=dstport)

            if family == 4:
                forward_nft_rules.append(forward_entry)
                accept_nft_rules.append(accept_entry)
            elif family == 6:
                forward_nft_rules_6.append(forward_entry)
                accept_nft_rules_6.append(accept_entry)

        forward_rule = (
            'table {family} {table} {{\n'
            '  chain {chain} {{\n'
            '   {rules}\n'
            '  }}\n'
            '}}\n'.format(
                family='ip',
                table='qubes-firewall-forward',
                chain='prerouting',
                rules='\n   '.join(forward_nft_rules)
            ))

        accept_rule = (
            'table {family} {table} {{\n'
            '  chain {chain} {{\n'
            '    {rules}\n'
            '  }}\n'
            '}}\n'.format(
                family='ip',
                table='qubes-firewall',
                chain='forward',
                rules='\n   '.join(accept_nft_rules)
            ))

        forward_rule += (
            'table {family} {table} {{\n'
            '  chain {chain} {{\n'
            '   {rules}\n'
            '  }}\n'
            '}}\n'.format(
                family='ip6',
                table='qubes-firewall-forward',
                chain='prerouting',
                rules='\n   '.join(forward_nft_rules_6)
            ))

        accept_rule += (
            'table {family} {table} {{\n'
            '  chain {chain} {{\n'
            '    {rules}\n'
            '  }}\n'
            '}}\n'.format(
                family='ip6',
                table='qubes-firewall',
                chain='forward',
                rules='\n   '.join(accept_nft_rules_6)
            ))

        return forward_rule + accept_rule


    def apply_rules_family(self, source, rules, family):
        """
        Apply rules for given source address.
        Handle only rules for given address family (IPv4 or IPv6).

        :param source: source address
        :param rules: rules list
        :param family: address family, either 4 or 6
        :return: None
        """

        chain = self.chain_for_addr(source)
        if chain not in self.chains[family]:
            self.create_chain(source, chain, family)

        (nft, dns) = self.prepare_rules(chain, rules, family)
        self.run_nft(nft)
        self.update_dns_info(source, dns)

    def apply_forward_rules(self, rules):
        """
        Apply rules for given source address.
        Handle only rules for given address family (IPv4 or IPv6).

        :param source: source address
        :param rules: rules list
        :param family: address family, either 4 or 6
        :return: None
        """

        if 'qubes-firewall-forward' not in self.chains[4]:
            self.create_forward_chain(4)

        if 'qubes-firewall-forward' not in self.chains[6]:
            self.create_forward_chain(6)

        nft = self.prepare_forward_rules(rules)
        self.run_nft(nft)

    def init(self):
        nft_init = (
            'table {family} qubes-firewall {{\n'
            '  chain forward {{\n'
            '    type filter hook forward priority 0;\n'
            '    policy drop;\n'
            '    ct state established,related accept\n'
            '    meta iifname != "vif*" accept\n'
            '  }}\n'
            '  chain prerouting {{\n'
            '    type filter hook prerouting priority -300;\n'
            '    policy accept;\n'
            '  }}\n'
            '  chain postrouting {{\n'
            '    type filter hook postrouting priority -300;\n'
            '    policy accept;\n'
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

    def forward_cleanup(self):
        nft_cleanup = (
            'delete table ip qubes-firewall-forward\n'
            'delete table ip6 qubes-firewall-forward\n'
        )
        self.run_nft(nft_cleanup)


def main():
    if shutil.which('nft'):
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
