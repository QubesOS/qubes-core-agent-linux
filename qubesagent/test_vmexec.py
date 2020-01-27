from unittest import TestCase
from unittest.mock import patch, call

from qubesagent.vmexec import main, decode, DecodeError


class TestVmExec(TestCase):
    def test_00_decode_simple(self):
        self.assertEqual(decode('echo+Hello'), [b'echo', b'Hello'])

    def test_01_decode_empty(self):
        self.assertEqual(decode('echo+'), [b'echo', b''])

    def test_02_decode_escaping(self):
        self.assertEqual(decode('echo+Hello-20world'),
                         [b'echo', b'Hello world'])
        self.assertEqual(decode('-0A-0D'),
                         [b'\n\r'])
        self.assertEqual(decode('-2Fbin-2Fls'),
                         [b'/bin/ls'])
        self.assertEqual(decode('ls+--la'),
                         [b'ls', b'-la'])
        self.assertEqual(decode('ls+---61'),
                         [b'ls', b'-a'])
        self.assertEqual(decode('ls+----help'),
                         [b'ls', b'--help'])

    def test_03_decode_errors(self):
        with self.assertRaises(DecodeError):
            decode('illegal/slash')
        with self.assertRaises(DecodeError):
            decode('illegal-singledash')
        with self.assertRaises(DecodeError):
            decode('smalletters-0a-0d')
        with self.assertRaises(DecodeError):
            decode('incompletebyte-A')
        with self.assertRaises(DecodeError):
            decode('incomplete-Abyte')
        with self.assertRaises(DecodeError):
            decode('ls+---threeslashes')

    def test_10_main_exec(self):
        with patch('os.execvp') as mock_execvp:
            main(['vmexec', 'ls+--la'])
            self.assertEqual(mock_execvp.call_args_list, [
                call(b'ls', [b'ls', b'-la'])])

    def test_11_main_fail(self):
        with self.assertRaises(SystemExit):
            main(['vmexec'])
        with self.assertRaises(SystemExit):
            main(['vmexec', 'illegal/slash'])
