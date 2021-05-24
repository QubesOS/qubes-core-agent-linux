import logging
import operator
import re
from unittest import TestCase
from unittest.mock import patch

import qubesagent.firewall


class DummyIptablesRestore(object):
    # pylint: disable=too-few-public-methods
    def __init__(self, worker_mock, family):
        self._worker_mock = worker_mock
        self._family = family
        self.returncode = 0

    def communicate(self, stdin=None):
        self._worker_mock.loaded_iptables[self._family] = stdin.decode()
        return ("", None)

class DummyQubesDB(object):
    def __init__(self, worker_mock):
        self._worker_mock = worker_mock
        self.entries = {}
        self.pending_watches = []

    def read(self, key):
        try:
            return self.entries[key]
        except KeyError:
            return None

    def rm(self, path):
        if path.endswith('/'):
            for key in list(self.entries):
                if key.startswith(path):
                    self.entries.pop(key)
        else:
            self.entries.pop(path)

    def write(self, path, val):
        self.entries[path] = val

    def multiread(self, prefix):
        result = {}
        for key, value in self.entries.items():
            if key.startswith(prefix):
                result[key] = value
        return result

    def list(self, prefix):
        result = []
        for key in self.entries.keys():
            if key.startswith(prefix):
                result.append(key)
        return result

    def watch(self, path):
        pass

    def read_watch(self):
        try:
            return self.pending_watches.pop(0)
        except IndexError:
            return None


class FirewallWorker(qubesagent.firewall.FirewallWorker):
    def __init__(self):
        # pylint: disable=super-init-not-called
        # don't call super on purpose - avoid connecting to QubesDB
        # super(FirewallWorker, self).__init__()
        self.qdb = DummyQubesDB(self)
        self.log = logging.getLogger('qubes.tests')

        self.init_called = False
        self.cleanup_called = False
        self.user_script_called = False
        self.update_connected_ips_called_with = []
        self.rules = {}

    def apply_rules(self, source_addr, rules):
        self.rules[source_addr] = rules

    def cleanup(self):
        self.init_called = True

    def init(self):
        self.cleanup_called = True

    def run_user_script(self):
        self.user_script_called = True

    def update_connected_ips(self, family):
        self.update_connected_ips_called_with.append(family)


class IptablesWorker(qubesagent.firewall.IptablesWorker):
    '''Override methods actually modifying system state to only log what
    would be done'''

    def __init__(self):
        # pylint: disable=super-init-not-called
        # don't call super on purpose - avoid connecting to QubesDB
        # super(IptablesWorker, self).__init__()
        # copied __init__:
        self.qdb = DummyQubesDB(self)
        self.log = logging.getLogger('qubes.tests')
        self.chains = {
            4: set(),
            6: set(),
        }

        #: instead of really running `iptables`, log what would be called
        self.called_commands = {
            4: [],
            6: [],
        }
        #: rules that would be loaded with `iptables-restore`
        self.loaded_iptables = {
            4: None,
            6: None,
        }

    def run_ipt(self, family, args, **kwargs):
        self.called_commands[family].append(args)

    def run_ipt_restore(self, family, args):
        return DummyIptablesRestore(self, family)

    @staticmethod
    def dns_addresses(family=None):
        if family == 4:
            return ['1.1.1.1', '2.2.2.2']
        else:
            return ['2001::1', '2001::2']


class NftablesWorker(qubesagent.firewall.NftablesWorker):
    '''Override methods actually modifying system state to only log what
    would be done'''

    def __init__(self):
        # pylint: disable=super-init-not-called
        # don't call super on purpose - avoid connecting to QubesDB
        # super(IptablesWorker, self).__init__()
        # copied __init__:
        self.qdb = DummyQubesDB(self)
        self.log = logging.getLogger('qubes.tests')
        self.chains = {
            4: set(),
            6: set(),
        }

        #: instead of really running `nft`, log what would be loaded
        #: rules that would be loaded with `nft`
        self.loaded_rules = []

    def run_nft(self, nft_input):
        self.loaded_rules.append(nft_input)

    @staticmethod
    def dns_addresses(family=None):
        if family == 4:
            return ['1.1.1.1', '2.2.2.2']
        else:
            return ['2001::1', '2001::2']

class WorkerCommon(object):
    def assertPrepareRulesDnsRet(self, dns_ret, expected_domain, family):
        self.assertEqual(dns_ret.keys(), {expected_domain})
        self.assertIsInstance(dns_ret[expected_domain], set)
        if family == 4:
            self.assertIsNotNone(re.match('^\d+\.\d+\.\d+\.\d+/32$',
                                dns_ret[expected_domain].pop()))
        elif family == 6:
            self.assertIsNotNone(re.match('^[0-9a-f:]+/\d+$',
                                dns_ret[expected_domain].pop()))
        else:
            raise ValueError()

    def test_701_dns_info(self):
        rules = [
            {'action': 'accept', 'proto': 'tcp',
                'dstports': '80-80', 'dsthost': 'ripe.net'},
            {'action': 'drop'},
        ]
        self.obj.apply_rules('10.137.0.1', rules)
        self.assertIsNotNone(self.obj.qdb.read('/dns/10.137.0.1/ripe.net'))
        self.obj.apply_rules('10.137.0.1', [{'action': 'drop'}])
        self.assertIsNone(self.obj.qdb.read('/dns/10.137.0.1/ripe.net'))

class TestIptablesWorker(TestCase, WorkerCommon):
    def setUp(self):
        super(TestIptablesWorker, self).setUp()
        self.obj = IptablesWorker()
        self.subprocess_patch = patch('subprocess.call')
        self.subprocess_mock = self.subprocess_patch.start()

    def tearDown(self):
        self.subprocess_patch.stop()

    def test_000_chain_for_addr(self):
        self.assertEqual(
            self.obj.chain_for_addr('10.137.0.1'), 'qbs-10-137-0-1')
        self.assertEqual(
            self.obj.chain_for_addr('fd09:24ef:4179:0000::3'),
            'qbs-09-24ef-4179-0000--3')

    def test_001_create_chain(self):
        testdata = [
            (4, '10.137.0.1', 'qbs-10-137-0-1'),
            (6, 'fd09:24ef:4179:0000::3', 'qbs-fd09-24ef-4179-0000--3')
        ]
        for family, addr, chain in testdata:
            self.obj.create_chain(addr, chain, family)
            self.assertEqual(self.obj.called_commands[family],
                [['-N', chain],
                    ['-I', 'QBS-FORWARD', '-s', addr, '-j', chain]])

    def test_002_prepare_rules4(self):
        rules = [
            {'action': 'accept', 'proto': 'tcp',
                'dstports': '80-80', 'dst4': '1.2.3.0/24'},
            {'action': 'accept', 'proto': 'udp',
                'dstports': '443-1024', 'dsthost': 'yum.qubes-os.org'},
            {'action': 'accept', 'specialtarget': 'dns'},
            {'action': 'drop', 'proto': 'udp', 'specialtarget': 'dns'},
            {'action': 'drop', 'proto': 'icmp'},
            {'action': 'drop'},
        ]
        expected_iptables = (
            "*filter\n"
            "-A chain -d 1.2.3.0/24 -p tcp --dport 80:80 -j ACCEPT\n"
            "-A chain -d 147.75.32.69/32 -p udp --dport 443:1024 -j ACCEPT\n"
            "-A chain -d 1.1.1.1/32 -p tcp --dport 53:53 -j ACCEPT\n"
            "-A chain -d 2.2.2.2/32 -p tcp --dport 53:53 -j ACCEPT\n"
            "-A chain -d 1.1.1.1/32 -p udp --dport 53:53 -j ACCEPT\n"
            "-A chain -d 2.2.2.2/32 -p udp --dport 53:53 -j ACCEPT\n"
            "-A chain -d 1.1.1.1/32 -p udp --dport 53:53 -j REJECT "
            "--reject-with icmp-admin-prohibited\n"
            "-A chain -d 2.2.2.2/32 -p udp --dport 53:53 -j REJECT "
            "--reject-with icmp-admin-prohibited\n"
            "-A chain -p icmp -j REJECT "
            "--reject-with icmp-admin-prohibited\n"
            "-A chain -j REJECT "
            "--reject-with icmp-admin-prohibited\n"
            "COMMIT\n"
        )
        ret = self.obj.prepare_rules('chain', rules, 4)
        self.assertEqual(ret[0], expected_iptables)
        self.assertPrepareRulesDnsRet(ret[1], 'yum.qubes-os.org', 4)
        with self.assertRaises(qubesagent.firewall.RuleParseError):
            self.obj.prepare_rules('chain', [{'unknown': 'xxx'}], 4)
        with self.assertRaises(qubesagent.firewall.RuleParseError):
            self.obj.prepare_rules('chain', [{'dst6': 'a::b'}], 4)
        with self.assertRaises(qubesagent.firewall.RuleParseError):
            self.obj.prepare_rules('chain', [{'dst4': '3.3.3.3'}], 6)

    def test_003_prepare_rules6(self):
        rules = [
            {'action': 'accept', 'proto': 'tcp',
                'dstports': '80-80', 'dst6': 'a::b/128'},
            {'action': 'accept', 'proto': 'tcp',
                'dsthost': 'ripe.net'},
            {'action': 'accept', 'specialtarget': 'dns'},
            {'action': 'drop', 'proto': 'udp', 'specialtarget': 'dns'},
            {'action': 'drop', 'proto': 'icmp'},
            {'action': 'drop'},
        ]
        expected_iptables = (
            "*filter\n"
            "-A chain -d a::b/128 -p tcp --dport 80:80 -j ACCEPT\n"
            "-A chain -d 2001:67c:2e8:22::c100:68b/128 -p tcp -j ACCEPT\n"
            "-A chain -d 2001::1/128 -p tcp --dport 53:53 -j ACCEPT\n"
            "-A chain -d 2001::2/128 -p tcp --dport 53:53 -j ACCEPT\n"
            "-A chain -d 2001::1/128 -p udp --dport 53:53 -j ACCEPT\n"
            "-A chain -d 2001::2/128 -p udp --dport 53:53 -j ACCEPT\n"
            "-A chain -d 2001::1/128 -p udp --dport 53:53 -j REJECT "
            "--reject-with icmp6-adm-prohibited\n"
            "-A chain -d 2001::2/128 -p udp --dport 53:53 -j REJECT "
            "--reject-with icmp6-adm-prohibited\n"
            "-A chain -p icmpv6 -j REJECT "
            "--reject-with icmp6-adm-prohibited\n"
            "-A chain -j REJECT "
            "--reject-with icmp6-adm-prohibited\n"
            "COMMIT\n"
        )
        ret = self.obj.prepare_rules('chain', rules, 6)
        self.assertEqual(ret[0], expected_iptables)
        self.assertPrepareRulesDnsRet(ret[1], 'ripe.net', 6)

    def test_004_apply_rules4(self):
        rules = [{'action': 'accept'}]
        chain = 'qbs-10-137-0-1'
        self.obj.apply_rules('10.137.0.1', rules)
        self.assertEqual(self.obj.called_commands[4],
            [
                ['-N', chain],
                ['-I', 'QBS-FORWARD', '-s', '10.137.0.1', '-j', chain],
                ['-F', chain]])
        self.assertEqual(self.obj.loaded_iptables[4],
            self.obj.prepare_rules(chain, rules, 4)[0])
        self.assertEqual(self.obj.called_commands[6], [])
        self.assertIsNone(self.obj.loaded_iptables[6])

    def test_005_apply_rules6(self):
        rules = [{'action': 'accept'}]
        chain = 'qbs-2000--a'
        self.obj.apply_rules('2000::a', rules)
        self.assertEqual(self.obj.called_commands[6],
            [
                ['-N', chain],
                ['-I', 'QBS-FORWARD', '-s', '2000::a', '-j', chain],
                ['-F', chain]])
        self.assertEqual(self.obj.loaded_iptables[6],
            self.obj.prepare_rules(chain, rules, 6)[0])
        self.assertEqual(self.obj.called_commands[4], [])
        self.assertIsNone(self.obj.loaded_iptables[4])

    def test_006_init(self):
        self.obj.init()
        self.assertEqual(self.obj.called_commands[4], [
            ['-F', 'QBS-FORWARD'],
            ['-A', 'QBS-FORWARD', '!', '-i', 'vif+', '-j', 'RETURN'],
            ['-A', 'QBS-FORWARD', '-j', 'DROP'],
            ['-t', 'raw', '-F', 'QBS-PREROUTING'],
            ['-t', 'mangle', '-F', 'QBS-POSTROUTING'],
        ])
        self.assertEqual(self.obj.called_commands[6], [
            ['-F', 'QBS-FORWARD'],
            ['-A', 'QBS-FORWARD', '!', '-i', 'vif+', '-j', 'RETURN'],
            ['-A', 'QBS-FORWARD', '-j', 'DROP'],
            ['-t', 'raw', '-F', 'QBS-PREROUTING'],
            ['-t', 'mangle', '-F', 'QBS-POSTROUTING'],
        ])

    def test_007_cleanup(self):
        self.obj.init()
        self.obj.create_chain('1.2.3.4', 'chain-ip4-1', 4)
        self.obj.create_chain('1.2.3.6', 'chain-ip4-2', 4)
        self.obj.create_chain('2000::1', 'chain-ip6-1', 6)
        self.obj.create_chain('2000::2', 'chain-ip6-2', 6)
        # forget about commands called earlier
        self.obj.called_commands[4] = []
        self.obj.called_commands[6] = []
        self.obj.cleanup()
        self.assertEqual([self.obj.called_commands[4][0]] +
                sorted(self.obj.called_commands[4][1:], key=operator.itemgetter(1)),
            [
                ['-F', 'QBS-FORWARD'],
                ['-F', 'chain-ip4-1'],
                ['-X', 'chain-ip4-1'],
                ['-F', 'chain-ip4-2'],
                ['-X', 'chain-ip4-2'],
                ['-t', 'mangle', '-F', 'QBS-POSTROUTING'],
                ['-t', 'raw', '-F', 'QBS-PREROUTING'],
            ])
        self.assertEqual([self.obj.called_commands[6][0]] +
                sorted(self.obj.called_commands[6][1:], key=operator.itemgetter(1)),
            [
                ['-F', 'QBS-FORWARD'],
                ['-F', 'chain-ip6-1'],
                ['-X', 'chain-ip6-1'],
                ['-F', 'chain-ip6-2'],
                ['-X', 'chain-ip6-2'],
                ['-t', 'mangle', '-F', 'QBS-POSTROUTING'],
                ['-t', 'raw', '-F', 'QBS-PREROUTING'],
            ])

    def test_008_update_connected_ips(self):
        self.obj.qdb.entries['/connected-ips'] = b'10.137.0.1 10.137.0.2'
        self.obj.called_commands[4] = []
        self.obj.update_connected_ips(4)

        self.assertEqual(self.obj.called_commands[4], [
            ['-t', 'raw', '-P', 'PREROUTING', 'DROP'],
            ['-t', 'mangle', '-P', 'POSTROUTING', 'DROP'],
            ['-t', 'raw', '-F', 'QBS-PREROUTING'],
            ['-t', 'mangle', '-F', 'QBS-POSTROUTING'],
            ['-t', 'raw', '-A', 'QBS-PREROUTING',
             '!', '-i', 'vif+', '-s', '10.137.0.1', '-j', 'DROP'],
            ['-t', 'mangle', '-A', 'QBS-POSTROUTING',
             '!', '-o', 'vif+', '-d', '10.137.0.1', '-j', 'DROP'],
            ['-t', 'raw', '-A', 'QBS-PREROUTING',
             '!', '-i', 'vif+', '-s', '10.137.0.2', '-j', 'DROP'],
            ['-t', 'mangle', '-A', 'QBS-POSTROUTING',
             '!', '-o', 'vif+', '-d', '10.137.0.2', '-j', 'DROP'],
            ['-t', 'raw', '-P', 'PREROUTING', 'ACCEPT'],
            ['-t', 'mangle', '-P', 'POSTROUTING', 'ACCEPT'],
        ])

    def test_009_update_connected_ips_empty(self):
        self.obj.qdb.entries['/connected-ips'] = b''
        self.obj.called_commands[4] = []
        self.obj.update_connected_ips(4)

        self.assertEqual(self.obj.called_commands[4], [
            ['-t', 'raw', '-F', 'QBS-PREROUTING'],
            ['-t', 'mangle', '-F', 'QBS-POSTROUTING'],
        ])

    def test_010_update_connected_ips_missing(self):
        self.obj.called_commands[4] = []
        self.obj.update_connected_ips(4)

        self.assertEqual(self.obj.called_commands[4], [
            ['-t', 'raw', '-F', 'QBS-PREROUTING'],
            ['-t', 'mangle', '-F', 'QBS-POSTROUTING'],
        ])

class TestNftablesWorker(TestCase, WorkerCommon):
    def setUp(self):
        super(TestNftablesWorker, self).setUp()
        self.obj = NftablesWorker()
        self.subprocess_patch = patch('subprocess.call')
        self.subprocess_mock = self.subprocess_patch.start()

    def tearDown(self):
        self.subprocess_patch.stop()

    def test_000_chain_for_addr(self):
        self.assertEqual(
            self.obj.chain_for_addr('10.137.0.1'), 'qbs-10-137-0-1')
        self.assertEqual(
            self.obj.chain_for_addr('fd09:24ef:4179:0000::3'),
            'qbs-fd09-24ef-4179-0000--3')

    def expected_create_chain(self, family, addr, chain):
        return (
            'table {family} qubes-firewall {{\n'
            '  chain {chain} {{\n'
            '  }}\n'
            '  chain forward {{\n'
            '    {family} saddr {addr} jump {chain}\n'
            '  }}\n'
            '}}\n'.format(family=family, addr=addr, chain=chain))

    def test_001_create_chain(self):
        testdata = [
            (4, '10.137.0.1', 'qbs-10-137-0-1'),
            (6, 'fd09:24ef:4179:0000::3', 'qbs-fd09-24ef-4179-0000--3')
        ]
        for family, addr, chain in testdata:
            self.obj.create_chain(addr, chain, family)
        self.assertEqual(self.obj.loaded_rules,
            [self.expected_create_chain('ip', '10.137.0.1', 'qbs-10-137-0-1'),
             self.expected_create_chain(
                 'ip6', 'fd09:24ef:4179:0000::3', 'qbs-fd09-24ef-4179-0000--3'),
             ])

    def test_002_prepare_rules4(self):
        rules = [
            {'action': 'accept', 'proto': 'tcp',
                'dstports': '80-80', 'dst4': '1.2.3.0/24'},
            {'action': 'accept', 'proto': 'udp',
                'dstports': '443-1024', 'dsthost': 'yum.qubes-os.org'},
            {'action': 'accept', 'specialtarget': 'dns'},
            {'action': 'drop', 'proto': 'udp', 'specialtarget': 'dns'},
            {'action': 'drop', 'proto': 'icmp'},
            {'action': 'drop'},
        ]
        expected_nft = (
            'flush chain ip qubes-firewall chain\n'
            'table ip qubes-firewall {\n'
            '  chain chain {\n'
            '    ip protocol tcp ip daddr 1.2.3.0/24 tcp dport 80 accept\n'
            '    ip protocol udp ip daddr { 147.75.32.69/32 } '
            'udp dport 443-1024 accept\n'
            '    ip daddr { 1.1.1.1/32, 2.2.2.2/32 } tcp dport 53 accept\n'
            '    ip daddr { 1.1.1.1/32, 2.2.2.2/32 } udp dport 53 accept\n'
            '    ip protocol udp ip daddr { 1.1.1.1/32, 2.2.2.2/32 } udp dport '
            '53 reject with icmp type admin-prohibited\n'
            '    ip protocol icmp reject with icmp type admin-prohibited\n'
            '    reject with icmp type admin-prohibited\n'
            '  }\n'
            '}\n'
        )
        ret = self.obj.prepare_rules('chain', rules, 4)
        self.assertEqual(ret[0], expected_nft)
        self.assertPrepareRulesDnsRet(ret[1], 'yum.qubes-os.org', 4)
        with self.assertRaises(qubesagent.firewall.RuleParseError):
            self.obj.prepare_rules('chain', [{'unknown': 'xxx'}], 4)
        with self.assertRaises(qubesagent.firewall.RuleParseError):
            self.obj.prepare_rules('chain', [{'dst6': 'a::b'}], 4)
        with self.assertRaises(qubesagent.firewall.RuleParseError):
            self.obj.prepare_rules('chain', [{'dst4': '3.3.3.3'}], 6)

    def test_003_prepare_rules6(self):
        rules = [
            {'action': 'accept', 'proto': 'tcp',
                'dstports': '80-80', 'dst6': 'a::b/128'},
            {'action': 'accept', 'proto': 'tcp',
                'dsthost': 'ripe.net'},
            {'action': 'accept', 'specialtarget': 'dns'},
            {'action': 'drop', 'proto': 'udp', 'specialtarget': 'dns'},
            {'action': 'drop', 'proto': 'icmp', 'icmptype': '128'},
            {'action': 'drop'},
        ]
        expected_nft = (
            'flush chain ip6 qubes-firewall chain\n'
            'table ip6 qubes-firewall {\n'
            '  chain chain {\n'
            '    ip6 nexthdr tcp ip6 daddr a::b/128 tcp dport 80 accept\n'
            '    ip6 nexthdr tcp ip6 daddr { 2001:67c:2e8:22::c100:68b/128 } '
            'accept\n'
            '    ip6 daddr { 2001::1/128, 2001::2/128 } tcp dport 53 accept\n'
            '    ip6 daddr { 2001::1/128, 2001::2/128 } udp dport 53 accept\n'
            '    ip6 nexthdr udp ip6 daddr { 2001::1/128, 2001::2/128 } '
            'udp dport 53 reject with icmpv6 type admin-prohibited\n'
            '    ip6 nexthdr icmpv6 icmpv6 type 128 reject with icmpv6 type '
            'admin-prohibited\n'
            '    reject with icmpv6 type admin-prohibited\n'
            '  }\n'
            '}\n'
        )
        ret = self.obj.prepare_rules('chain', rules, 6)
        self.assertEqual(ret[0], expected_nft)
        self.assertPrepareRulesDnsRet(ret[1], 'ripe.net', 6)

    def test_004_apply_rules4(self):
        rules = [{'action': 'accept'}]
        chain = 'qbs-10-137-0-1'
        self.obj.apply_rules('10.137.0.1', rules)
        self.assertEqual(self.obj.loaded_rules,
            [self.expected_create_chain('ip', '10.137.0.1', chain),
             self.obj.prepare_rules(chain, rules, 4)[0],
             ])

    def test_005_apply_rules6(self):
        rules = [{'action': 'accept'}]
        chain = 'qbs-2000--a'
        self.obj.apply_rules('2000::a', rules)
        self.assertEqual(self.obj.loaded_rules,
            [self.expected_create_chain('ip6', '2000::a', chain),
             self.obj.prepare_rules(chain, rules, 6)[0],
             ])

    def test_006_init(self):
        self.obj.init()
        self.assertEqual(self.obj.loaded_rules,
        [
            'table ip qubes-firewall {\n'
            '  chain forward {\n'
            '    type filter hook forward priority 0;\n'
            '    policy drop;\n'
            '    ct state established,related accept\n'
            '    meta iifname != "vif*" accept\n'
            '  }\n'
            '  chain prerouting {\n'
            '    type filter hook prerouting priority -300;\n'
            '    policy accept;\n'
            '  }\n'
            '  chain postrouting {\n'
            '    type filter hook postrouting priority -300;\n'
            '    policy accept;\n'
            '  }\n'
            '}\n'
            'table ip6 qubes-firewall {\n'
            '  chain forward {\n'
            '    type filter hook forward priority 0;\n'
            '    policy drop;\n'
            '    ct state established,related accept\n'
            '    meta iifname != "vif*" accept\n'
            '  }\n'
            '  chain prerouting {\n'
            '    type filter hook prerouting priority -300;\n'
            '    policy accept;\n'
            '  }\n'
            '  chain postrouting {\n'
            '    type filter hook postrouting priority -300;\n'
            '    policy accept;\n'
            '  }\n'
            '}\n'
        ])

    def test_007_cleanup(self):
        self.obj.init()
        self.obj.create_chain('1.2.3.4', 'chain-ip4-1', 4)
        self.obj.create_chain('1.2.3.6', 'chain-ip4-2', 4)
        self.obj.create_chain('2000::1', 'chain-ip6-1', 6)
        self.obj.create_chain('2000::2', 'chain-ip6-2', 6)
        # forget about commands called earlier
        self.obj.loaded_rules = []
        self.obj.cleanup()
        self.assertEqual(self.obj.loaded_rules,
            ['delete table ip qubes-firewall\n'
             'delete table ip6 qubes-firewall\n',
            ])

    def test_008_update_connected_ips(self):
        self.obj.qdb.entries['/connected-ips'] = b'10.137.0.1 10.137.0.2'
        self.obj.loaded_rules = []
        self.obj.update_connected_ips(4)

        self.assertEqual(self.obj.loaded_rules, [
            'flush chain ip qubes-firewall prerouting\n'
            'flush chain ip qubes-firewall postrouting\n'
            'table ip qubes-firewall {\n'
            '  chain prerouting {\n'
            '    iifname != "vif*" ip saddr {10.137.0.1, 10.137.0.2} drop\n'
            '  }\n'
            '  chain postrouting {\n'
            '    oifname != "vif*" ip daddr {10.137.0.1, 10.137.0.2} drop\n'
            '  }\n'
            '}\n'
        ])

    def test_009_update_connected_ips_empty(self):
        self.obj.qdb.entries['/connected-ips'] = b''
        self.obj.loaded_rules = []
        self.obj.update_connected_ips(4)

        self.assertEqual(self.obj.loaded_rules, [
            'flush chain ip qubes-firewall prerouting\n'
            'flush chain ip qubes-firewall postrouting\n'
        ])

    def test_010_update_connected_ips_missing(self):
        self.obj.loaded_rules = []
        self.obj.update_connected_ips(4)

        self.assertEqual(self.obj.loaded_rules, [
            'flush chain ip qubes-firewall prerouting\n'
            'flush chain ip qubes-firewall postrouting\n'
        ])

class TestFirewallWorker(TestCase):
    def setUp(self):
        self.obj = FirewallWorker()
        rules = {
            '10.137.0.1': {
                'policy': b'accept',
                '0000': b'proto=tcp dstports=80-80 action=drop',
                '0001': b'proto=udp specialtarget=dns action=accept',
                '0002': b'proto=udp action=drop',
            },
            '10.137.0.2': {'policy': b'accept'},
            # no policy
            '10.137.0.3': {'0000': b'proto=tcp action=accept'},
            # no action
            '10.137.0.4': {
                'policy': b'drop',
                '0000': b'proto=tcp'
            },
        }
        for addr, entries in rules.items():
            for key, value in entries.items():
                self.obj.qdb.entries[
                    '/qubes-firewall/{}/{}'.format(addr, key)] = value

        self.subprocess_patch = patch('subprocess.call')
        self.subprocess_mock = self.subprocess_patch.start()

    def tearDown(self):
        self.subprocess_patch.stop()

    def test_read_rules(self):
        expected_rules1 = [
            {'proto': 'tcp', 'dstports': '80-80', 'action': 'drop'},
            {'proto': 'udp', 'specialtarget': 'dns', 'action': 'accept'},
            {'proto': 'udp', 'action': 'drop'},
            {'action': 'accept'},
        ]
        expected_rules2 = [
            {'action': 'accept'},
        ]
        self.assertEqual(self.obj.read_rules('10.137.0.1'), expected_rules1)
        self.assertEqual(self.obj.read_rules('10.137.0.2'), expected_rules2)
        with self.assertRaises(qubesagent.firewall.RuleParseError):
            self.obj.read_rules('10.137.0.3')
        with self.assertRaises(qubesagent.firewall.RuleParseError):
            self.obj.read_rules('10.137.0.4')


    def test_list_targets(self):
        self.assertEqual(self.obj.list_targets(), set(['10.137.0.{}'.format(x)
            for x in range(1, 5)]))

    def test_is_ip6(self):
        self.assertTrue(self.obj.is_ip6('2000::abcd'))
        self.assertTrue(self.obj.is_ip6('2000:1:2:3:4:5:6:abcd'))
        self.assertFalse(self.obj.is_ip6('10.137.0.1'))

    def test_handle_addr(self):
        self.obj.handle_addr('10.137.0.2')
        self.assertEqual(self.obj.rules['10.137.0.2'], [{'action': 'accept'}])
        self.assertEqual(self.obj.qdb.entries['/qubes-firewall-handled/10.137.0.2'], '1')
        self.obj.handle_addr('10.137.0.2')
        self.assertEqual(self.obj.rules['10.137.0.2'], [{'action': 'accept'}])
        self.assertEqual(self.obj.qdb.entries['/qubes-firewall-handled/10.137.0.2'], '2')
        # fallback to block all
        self.obj.handle_addr('10.137.0.3')
        self.assertEqual(self.obj.rules['10.137.0.3'], [{'action': 'drop'}])
        self.assertEqual(self.obj.qdb.entries['/qubes-firewall-handled/10.137.0.3'], '1')
        self.obj.handle_addr('10.137.0.4')
        self.assertEqual(self.obj.rules['10.137.0.4'], [{'action': 'drop'}])
        self.assertEqual(self.obj.qdb.entries['/qubes-firewall-handled/10.137.0.4'], '1')

    @patch('os.path.isfile')
    @patch('os.access')
    @patch('subprocess.call')
    def test_run_user_script(self, mock_subprocess, mock_os_access,
            mock_os_path_isfile):
        mock_os_path_isfile.return_value = False
        mock_os_access.return_value = False
        super(FirewallWorker, self.obj).run_user_script()
        self.assertFalse(mock_subprocess.called)

        mock_os_path_isfile.return_value = True
        mock_os_access.return_value = False
        super(FirewallWorker, self.obj).run_user_script()
        self.assertFalse(mock_subprocess.called)

        mock_os_path_isfile.return_value = True
        mock_os_access.return_value = True
        super(FirewallWorker, self.obj).run_user_script()
        mock_subprocess.assert_called_once_with(
            ['/rw/config/qubes-firewall-user-script'])

    def test_main(self):
        self.obj.main()
        self.assertTrue(self.obj.init_called)
        self.assertTrue(self.obj.cleanup_called)
        self.assertTrue(self.obj.user_script_called)
        self.assertEqual(self.obj.update_connected_ips_called_with, [4, 6])
        self.assertEqual(set(self.obj.rules.keys()), self.obj.list_targets())
        # rules content were already tested
