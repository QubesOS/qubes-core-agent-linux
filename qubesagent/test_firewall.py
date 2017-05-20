import logging
import operator
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
        self._worker_mock.loaded_iptables[self._family] = stdin
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
        self.rules = {}

    def apply_rules(self, source_addr, rules):
        self.rules[source_addr] = rules

    def cleanup(self):
        self.init_called = True

    def init(self):
        self.cleanup_called = True


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


class TestIptablesWorker(TestCase):
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
            'qbs-fd09-24ef-4179-0000--3')

    def test_001_create_chain(self):
        testdata = [
            (4, '10.137.0.1', 'qbs-10-137-0-1'),
            (6, 'fd09:24ef:4179:0000::3', 'qbs-fd09-24ef-4179-0000--3')
        ]
        for family, addr, chain in testdata:
            self.obj.create_chain(addr, chain, family)
            self.assertEqual(self.obj.called_commands[family],
                [['-N', chain],
                    ['-A', 'QBS-FORWARD', '-s', addr, '-j', chain]])

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
            "-A chain -d 82.94.215.165/32 -p udp --dport 443:1024 -j ACCEPT\n"
            "-A chain -d 1.1.1.1/32 -p tcp --dport 53:53 -j ACCEPT\n"
            "-A chain -d 2.2.2.2/32 -p tcp --dport 53:53 -j ACCEPT\n"
            "-A chain -d 1.1.1.1/32 -p udp --dport 53:53 -j ACCEPT\n"
            "-A chain -d 2.2.2.2/32 -p udp --dport 53:53 -j ACCEPT\n"
            "-A chain -d 1.1.1.1/32 -p udp --dport 53:53 -j DROP\n"
            "-A chain -d 2.2.2.2/32 -p udp --dport 53:53 -j DROP\n"
            "-A chain -p icmp -j DROP\n"
            "-A chain -j DROP\n"
            "COMMIT\n"
        )
        self.assertEqual(self.obj.prepare_rules('chain', rules, 4),
            expected_iptables)
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
            "-A chain -d 2001::1/128 -p udp --dport 53:53 -j DROP\n"
            "-A chain -d 2001::2/128 -p udp --dport 53:53 -j DROP\n"
            "-A chain -p icmp -j DROP\n"
            "-A chain -j DROP\n"
            "COMMIT\n"
        )
        self.assertEqual(self.obj.prepare_rules('chain', rules, 6),
            expected_iptables)

    def test_004_apply_rules4(self):
        rules = [{'action': 'accept'}]
        chain = 'qbs-10-137-0-1'
        self.obj.apply_rules('10.137.0.1', rules)
        self.assertEqual(self.obj.called_commands[4],
            [
                ['-N', chain],
                ['-A', 'QBS-FORWARD', '-s', '10.137.0.1', '-j', chain],
                ['-F', chain]])
        self.assertEqual(self.obj.loaded_iptables[4],
            self.obj.prepare_rules(chain, rules, 4))
        self.assertEqual(self.obj.called_commands[6], [])
        self.assertIsNone(self.obj.loaded_iptables[6])

    def test_005_apply_rules6(self):
        rules = [{'action': 'accept'}]
        chain = 'qbs-2000--a'
        self.obj.apply_rules('2000::a', rules)
        self.assertEqual(self.obj.called_commands[6],
            [
                ['-N', chain],
                ['-A', 'QBS-FORWARD', '-s', '2000::a', '-j', chain],
                ['-F', chain]])
        self.assertEqual(self.obj.loaded_iptables[6],
            self.obj.prepare_rules(chain, rules, 6))
        self.assertEqual(self.obj.called_commands[4], [])
        self.assertIsNone(self.obj.loaded_iptables[4])

    def test_006_init(self):
        self.obj.init()
        self.assertEqual(self.obj.called_commands[4],
            [['-nL', 'QBS-FORWARD']])
        self.assertEqual(self.obj.called_commands[6],
            [['-nL', 'QBS-FORWARD']])

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
            [['-F', 'QBS-FORWARD'],
                ['-F', 'chain-ip4-1'],
                ['-X', 'chain-ip4-1'],
                ['-F', 'chain-ip4-2'],
                ['-X', 'chain-ip4-2']])
        self.assertEqual([self.obj.called_commands[6][0]] +
                sorted(self.obj.called_commands[6][1:], key=operator.itemgetter(1)),
            [['-F', 'QBS-FORWARD'],
                ['-F', 'chain-ip6-1'],
                ['-X', 'chain-ip6-1'],
                ['-F', 'chain-ip6-2'],
                ['-X', 'chain-ip6-2']])


class TestNftablesWorker(TestCase):
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
            '    ip protocol udp ip daddr { 82.94.215.165/32 } '
            'udp dport 443-1024 accept\n'
            '    ip daddr { 1.1.1.1/32, 2.2.2.2/32 } tcp dport 53 accept\n'
            '    ip daddr { 1.1.1.1/32, 2.2.2.2/32 } udp dport 53 accept\n'
            '    ip protocol udp ip daddr { 1.1.1.1/32, 2.2.2.2/32 } udp dport '
            '53 drop\n'
            '    ip protocol icmp drop\n'
            '    drop\n'
            '  }\n'
            '}\n'
        )
        self.assertEqual(self.obj.prepare_rules('chain', rules, 4),
            expected_nft)
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
            'udp dport 53 drop\n'
            '    ip6 nexthdr icmpv6 icmpv6 type 128 drop\n'
            '    drop\n'
            '  }\n'
            '}\n'
        )
        self.assertEqual(self.obj.prepare_rules('chain', rules, 6),
            expected_nft)

    def test_004_apply_rules4(self):
        rules = [{'action': 'accept'}]
        chain = 'qbs-10-137-0-1'
        self.obj.apply_rules('10.137.0.1', rules)
        self.assertEqual(self.obj.loaded_rules,
            [self.expected_create_chain('ip', '10.137.0.1', chain),
             self.obj.prepare_rules(chain, rules, 4),
             ])

    def test_005_apply_rules6(self):
        rules = [{'action': 'accept'}]
        chain = 'qbs-2000--a'
        self.obj.apply_rules('2000::a', rules)
        self.assertEqual(self.obj.loaded_rules,
            [self.expected_create_chain('ip6', '2000::a', chain),
             self.obj.prepare_rules(chain, rules, 6),
             ])

    def test_006_init(self):
        self.obj.init()
        self.assertEqual(self.obj.loaded_rules,
        [
            'table ip qubes-firewall {\n'
            '  chain forward {\n'
            '    type filter hook forward priority 0;\n'
            '  }\n'
            '}\n'
            'table ip6 qubes-firewall {\n'
            '  chain forward {\n'
            '    type filter hook forward priority 0;\n'
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

class TestFirewallWorker(TestCase):
    def setUp(self):
        self.obj = FirewallWorker()
        rules = {
            '10.137.0.1': {
                'policy': 'accept',
                '0000': 'proto=tcp dstports=80-80 action=drop',
                '0001': 'proto=udp specialtarget=dns action=accept',
                '0002': 'proto=udp action=drop',
            },
            '10.137.0.2': {'policy': 'accept'},
            # no policy
            '10.137.0.3': {'0000': 'proto=tcp action=accept'},
            # no action
            '10.137.0.4': {
                'policy': 'drop',
                '0000': 'proto=tcp'
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
        # fallback to block all
        self.obj.handle_addr('10.137.0.3')
        self.assertEqual(self.obj.rules['10.137.0.3'], [{'action': 'drop'}])
        self.obj.handle_addr('10.137.0.4')
        self.assertEqual(self.obj.rules['10.137.0.4'], [{'action': 'drop'}])


    def test_main(self):
        self.obj.main()
        self.assertTrue(self.obj.init_called)
        self.assertTrue(self.obj.cleanup_called)
        self.assertEqual(set(self.obj.rules.keys()), self.obj.list_targets())
        # rules content were already tested
