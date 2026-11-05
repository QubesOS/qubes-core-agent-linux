"""Opt-in integration test: run as root with QUBES_TEST_SYSTEMD=1.

Requires systemd and nftables. Firewall changes are confined to the transient
service's private network namespace; no QubesDB daemon is needed.
"""
import configparser
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

from qubesagent.firewall import NftablesWorker, RuleApplyError


def shutdown_worker(result_path):
    """Exercise graceful stop inside the transient service."""
    with patch('qubesdb.QubesDB', create=True):
        worker = NftablesWorker()
    worker.init()
    worker.run_nft('add table inet unrelated\n')
    # A helper already running when stop begins must be allowed to finish.
    # Checking this directly avoids relying on the timing of the race where
    # systemd signals nft after cleanup has launched it.
    with subprocess.Popen(
            [sys.executable, '-c',
             'import sys; print("ready", flush=True); sys.stdin.read()'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE) as helper:
        assert helper.stdout.readline() == b'ready\n'
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
        worker.sd_notify('READY=1')
        signal.sigwait({signal.SIGTERM})
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM})
        helper.communicate(timeout=5)
        assert helper.returncode == 0, helper.returncode
    worker.cleanup()
    assert subprocess.check_output(['nft', 'list', 'tables']) == \
        b'table inet unrelated\n'
    # Repeated deletion is not a normal shutdown path. A missing table must
    # still be reported, rather than hiding arbitrary nft failures.
    try:
        worker.cleanup()
    except RuleApplyError:
        pass
    else:
        raise AssertionError('Repeated cleanup unexpectedly succeeded')
    Path(result_path).write_text('clean shutdown', encoding='ascii')


@unittest.skipUnless(os.environ.get('QUBES_TEST_SYSTEMD') == '1',
                     'requires opt-in root/systemd/nftables environment')
class TestFirewallShutdown(unittest.TestCase):
    """Check the shipped service's shutdown policy with real subprocesses."""

    def test_service_stop(self):
        """Allow helpers to finish and remove only the firewall's own tables."""
        root = Path(__file__).resolve().parent.parent
        config = configparser.ConfigParser()
        config.read(root / 'vm-systemd/qubes-firewall.service')
        kill_mode = config.get('Service', 'KillMode', fallback='control-group')
        unit = 'qubes-firewall-test-' + uuid.uuid4().hex
        with tempfile.TemporaryDirectory() as directory:
            result_path = Path(directory) / 'result'
            try:
                subprocess.run([
                    'systemd-run', '--quiet', '--unit=' + unit,
                    '--property=Type=notify', '--property=PrivateNetwork=yes',
                    '--property=TimeoutStartSec=15',
                    '--property=TimeoutStopSec=15',
                    '--property=KillMode=' + kill_mode,
                    '--working-directory=' + str(root),
                    '--setenv=PYTHONPATH=' + str(root / 'test-packages'),
                    sys.executable, '-m', 'qubesagent.test_firewall_shutdown',
                    str(result_path),
                ], check=True, timeout=20)
                subprocess.run(['systemctl', 'stop', unit],
                               check=True, timeout=20)
                journal = subprocess.check_output(
                    ['journalctl', '-u', unit, '--no-pager'], text=True)
                self.assertTrue(result_path.exists(), journal)
                self.assertEqual(result_path.read_text(encoding='ascii'),
                                 'clean shutdown')
            finally:
                subprocess.run(['systemctl', 'stop', unit], check=False,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=20)
                subprocess.run(['systemctl', 'reset-failed', unit], check=False,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=20)


if __name__ == '__main__':
    shutdown_worker(sys.argv[1])
