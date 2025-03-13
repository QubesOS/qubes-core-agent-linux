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
import ipaddress
import subprocess
import pwd
import shutil

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

    def apply_rules(self, source_addr, rules):
        """Apply rules in given source address"""
        raise NotImplementedError

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
            path = '/dns/{}/{}'.format(source, host)
            try:
                self.qdb.write(path, str(hostaddrs))
            except Exception as err:
                if len(path) > 64 and err.args == (0, 'Error'):
                    self.log.error(('Unable to add DNS information for {} ({})'
                        ' due to qubesdb path length limit').format(
                            host, source))
                    self.log.error('See https://github.com/QubesOS/'
                        'qubes-issues/9085')
                else:
                    raise

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
        return set(t.split('/')[2] for t in self.qdb.list('/qubes-firewall/'))

    def conntrack_drop(self, src, con):
        subprocess.run(['conntrack', '-D', '--src', src, '--dst', con[1],
                        '--proto', con[0], '--dport', con[2]],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)

    def conntrack_get_connections(self, family, source):
        connections = set()

        with subprocess.Popen(['conntrack', '-L',
                               '--family', f'ipv{family}', '--src', source],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL) as p:
            while True:
                line = p.stdout.readline()
                if not line:
                    break

                line_split = line.decode().split(' ')

                proto = line_split[0]
                dst = None
                dport = None
                for i in line_split:
                    if i.startswith('dst='):
                        dst = i[len('dst='):]
                    elif i.startswith('dport='):
                        dport = i[len('dport='):]
                        break

                if not dst or not dport:
                    continue

                connections.add((proto, dst, dport))

        return connections

    def is_blocked(self, rules, con, dns):
        con_proto, con_dst, con_dport = con

        family = 6 if self.is_ip6(con_dst) else 4
        dns_servers = list(self.dns_addresses(family))
        fullmask = '/128' if family == 6 else '/32'

        for rule in rules:
            if rule.get('proto') and rule['proto'] != con_proto:
                continue

            if rule.get('dstports'):
                if '-' in rule['dstports']:
                    rule_port_range = rule['dstports'].split('-')
                    if not (rule_port_range[0] <= con_dport and \
                            con_dport <= rule_port_range[1]):
                        continue
                else:
                    if con_dport != rule['dstports']:
                        continue

            if family == 4 and rule.get('dst6') or \
               family == 6 and rule.get('dst4'):
                continue

            if rule.get(f'dst{family}'):
                if not ipaddress.ip_address(con_dst) in \
                   ipaddress.ip_network(rule[f'dst{family}'], False):
                    continue
            elif rule.get('dsthost'):
                if not f'{con_dst}{fullmask}' in dns[rule['dsthost']]:
                    continue

            if rule.get('specialtarget') == 'dns':
                if int(con_dport) != 53 or not con_dst in dns_servers:
                    continue

            return rule['action'] == 'drop'

        # Blocked by default
        return True

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
        self.qdb.watch('/connected-ips')
        self.qdb.watch('/connected-ips6')
        # initial load
        for source_addr in self.list_targets():
            self.handle_addr(source_addr)
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

        except OSError:  # EINTR
            # signal received, don't continue the loop
            pass

        self.cleanup()

    def terminate(self):
        self.terminate_requested = True

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

        connections = self.conntrack_get_connections(family, source)
        for con in connections:
            is_blocked = self.is_blocked(rules, con, dns)
            if is_blocked:
                self.conntrack_drop(source, con)

    def apply_rules(self, source, rules):
        if self.is_ip6(source):
            self.apply_rules_family(source, rules, 6)
        else:
            self.apply_rules_family(source, rules, 4)

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


def main():
    if shutil.which('nft'):
        worker = NftablesWorker()
    else:
        print('Sorry, iptables no longer supported', file=sys.stderr)
        sys.exit(1)
    signal.signal(signal.SIGTERM, lambda _signal, _stack: worker.terminate())
    worker.main()


if __name__ == '__main__':
    main()
