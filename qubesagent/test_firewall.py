import logging
import operator
import re
from io import BytesIO
from unittest import TestCase
from unittest.mock import patch, Mock

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
        if len(path) > 64:
            raise DummyQubesDBError(0, 'Error')
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

class DummyQubesDBError(Exception):
    "Raised by QubesDB"

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
        # super(NftablesWorker, self).__init__()
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
            self.assertIsNotNone(re.match(r'^\d+\.\d+\.\d+\.\d+/32$',
                                dns_ret[expected_domain].pop()))
        elif family == 6:
            self.assertIsNotNone(re.match(r'^[0-9a-f:]+/\d+$',
                                dns_ret[expected_domain].pop()))
        else:
            raise ValueError()

    def test_701_dns_info(self):
        self.obj.conntrack_get_connections = Mock(return_value=[])
        rules = [
            {'action': 'accept', 'proto': 'tcp',
                'dstports': '80-80', 'dsthost': 'ripe.net'},
            {'action': 'drop'},
        ]
        self.obj.apply_rules('10.137.0.1', rules)
        self.assertIsNotNone(self.obj.qdb.read('/dns/10.137.0.1/ripe.net'))
        self.obj.apply_rules('10.137.0.1', [{'action': 'drop'}])
        self.assertIsNone(self.obj.qdb.read('/dns/10.137.0.1/ripe.net'))

    def test_702_dns_info_qubesdb_path_length_crash(self):
        self.obj.conntrack_get_connections = Mock(return_value=[])
        rules = [
            {'action': 'accept', 'proto': 'tcp',
                'dstports': '443-443', 'dsthost': 'www.google.com'},
            {'action': 'accept', 'proto': 'tcp',
                'dstports': '443-443', 'dsthost': 'prod-dynamite-prod-05-us-signaler-pa.clients6.google.com'},
            {'action': 'drop'},
        ]
        self.obj.apply_rules('10.137.0.22', rules)
        self.assertIsNotNone(self.obj.qdb.read('/dns/10.137.0.22/www.google.com'))
        # Unfortunately, this is assertIsNone until the QubesDB path length limit is raised.
        self.assertIsNone(self.obj.qdb.read('/dns/10.137.0.22/prod-dynamite-prod-05-us-signaler-pa.clients6.google.com'))
        self.obj.apply_rules('10.137.0.22', [{'action': 'drop'}])
        self.assertIsNone(self.obj.qdb.read('/dns/10.137.0.22/www.google.com'))
        self.assertIsNone(self.obj.qdb.read('/dns/10.137.0.22/prod-dynamite-prod-05-us-signaler-pa.clients6.google.com'))

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
            '  chain qubes-forward {{\n'
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
            'flush set ip qubes-firewall dns-addr\n'
            'add element ip qubes-firewall dns-addr { 1.1.1.1, 2.2.2.2 }\n'
            'flush chain ip qubes-firewall chain\n'
            'table ip qubes-firewall {\n'
            '  chain chain {\n'
            '    ip protocol tcp ip daddr 1.2.3.0/24 tcp dport 80 accept\n'
            '    ip protocol udp ip daddr { 193.219.28.150/32 } '
            'udp dport 443-1024 accept\n'
            '    ip daddr @dns-addr tcp dport 53 accept\n'
            '    ip daddr @dns-addr udp dport 53 accept\n'
            '    ip protocol udp ip daddr @dns-addr udp dport '
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
            'flush set ip6 qubes-firewall dns-addr\n'
            'add element ip6 qubes-firewall dns-addr { 2001::1, 2001::2 }\n'
            'flush chain ip6 qubes-firewall chain\n'
            'table ip6 qubes-firewall {\n'
            '  chain chain {\n'
            '    ip6 nexthdr tcp ip6 daddr a::b/128 tcp dport 80 accept\n'
            '    ip6 nexthdr tcp ip6 daddr { 2001:67c:2e8:25::c100:b33/128 } '
            'accept\n'
            '    ip6 daddr @dns-addr tcp dport 53 accept\n'
            '    ip6 daddr @dns-addr udp dport 53 accept\n'
            '    ip6 nexthdr udp ip6 daddr @dns-addr '
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
        self.obj.conntrack_get_connections = Mock(return_value=[])
        rules = [{'action': 'accept'}]
        chain = 'qbs-10-137-0-1'
        self.obj.apply_rules('10.137.0.1', rules)
        self.assertEqual(self.obj.loaded_rules,
            [self.expected_create_chain('ip', '10.137.0.1', chain),
             self.obj.prepare_rules(chain, rules, 4)[0],
             ])

    def test_005_apply_rules6(self):
        self.obj.conntrack_get_connections = Mock(return_value=[])
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
            '  set dns-addr {\n'
            '    type ipv4_addr\n'
            '  }\n'
            '  chain qubes-forward {\n'
            '  }\n'
            '  chain forward {\n'
            '    type filter hook forward priority 0;\n'
            '    policy drop;\n'
            '    ct state established,related accept\n'
            '    meta iifname != "vif*" accept\n'
            '    jump qubes-forward\n'
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
            '  set dns-addr {\n'
            '    type ipv6_addr\n'
            '  }\n'
            '  chain qubes-forward {\n'
            '  }\n'
            '  chain forward {\n'
            '    type filter hook forward priority 0;\n'
            '    policy drop;\n'
            '    ct state established,related accept\n'
            '    meta iifname != "vif*" accept\n'
            '    jump qubes-forward\n'
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

    @patch('subprocess.Popen')
    def test_conntrack_get_connections(self, mock_subprocess):
        conntrack_stdout = (
            b'tcp      6 431963 ESTABLISHED src=10.138.38.13 dst=1.1.1.1 '
                b'sport=34488 dport=443 src=1.1.1.1 dst=10.138.38.13 sport=443 '
                b'dport=34488 [ASSURED] mark=0 use=1\n'

            b'udp      17 3 src=10.138.38.13 dst=10.139.1.1 sport=33295 dport=53 '
                b'src=10.139.1.1 dst=10.138.38.13 sport=53 dport=33295 mark=0 use=1\n'
        )
        mock_subprocess().__enter__().stdout = BytesIO(conntrack_stdout)
        ret = self.obj.conntrack_get_connections(4, "10.138.38.13")
        self.assertEqual(ret, {
            ('udp', '10.139.1.1', '53'),
            ('tcp', '1.1.1.1', '443')
        })

    def test_is_blocked(self):
        dns_servers_ipv4 = list(self.obj.dns_addresses(4))
        dns_servers_ipv6 = list(self.obj.dns_addresses(6))
        dns = {
            "example.com": set(["1.2.3.4/32", "4.3.2.1/32"]),
            "example2.com": set(["2001::1/128", "2001::2/128"])
        }
        rules = [
            {'proto': 'tcp', 'dstports': '80-80', 'action': 'drop'},
            {'proto': 'tcp', 'dstports': '90-92', 'action': 'drop'},
            {'proto': 'tcp', 'dsthost': 'example.com', 'action': 'drop'},
            {'proto': 'tcp', 'dsthost': 'example2.com', 'action': 'drop'},
            {'dst4': '3.3.3.3/32', 'action': 'drop'},
            {'dst4': '4.4.4.4/24', 'action': 'drop'},
            {'dst6': '2002::3/128', 'action': 'drop'},
            {'dst6': '2003::3/112', 'action': 'drop'},
            {'proto': 'udp', 'specialtarget': 'dns', 'action': 'drop'},
            {'action': 'accept'},
        ]

        self.assertTrue(self.obj.is_blocked({}, ("tcp", "1.1.1.1", "123"), dns))

        self.assertFalse(self.obj.is_blocked(rules, ("tcp", "10.0.0.1", "443"), dns))
        self.assertFalse(self.obj.is_blocked(rules, ("udp", "10.0.0.1", "80"), dns))
        self.assertTrue(self.obj.is_blocked(rules, ("tcp", "10.0.0.1", "80"), dns))
        self.assertTrue(self.obj.is_blocked(rules, ("tcp", "10.0.0.1", "91"), dns))
        self.assertTrue(self.obj.is_blocked(rules, ("tcp", "1.2.3.4", "123"), dns))
        self.assertTrue(self.obj.is_blocked(rules, ("tcp", "4.3.2.1", "123"), dns))
        self.assertTrue(self.obj.is_blocked(rules, ("tcp", "2003::2", "123"), dns))
        self.assertTrue(self.obj.is_blocked(rules, ("tcp", "3.3.3.3", "123"), dns))
        self.assertTrue(self.obj.is_blocked(rules, ("tcp", "4.4.4.8", "123"), dns))
        self.assertTrue(self.obj.is_blocked(rules, ("tcp", "2002::3", "123"), dns))
        self.assertTrue(self.obj.is_blocked(rules, ("tcp", "2003::5", "123"), dns))

        for server in dns_servers_ipv4:
            self.assertTrue(self.obj.is_blocked(rules, ("udp", server, "53"), dns))

        for server in dns_servers_ipv6:
            self.assertTrue(self.obj.is_blocked(rules, ("udp", server, "53"), dns))
