import os
import os.path
import shutil
import subprocess
import tempfile
import unittest

BIN = os.path.join(os.path.dirname(__file__), '..', 'qubes-rpc')
assert os.path.isdir(BIN)

MISSING_FOR_FILECOPY = [f for f in ['qfile-agent', 'qfile-unpacker']
                        if not os.path.exists(os.path.join(BIN, f))]

@unittest.skipIf(MISSING_FOR_FILECOPY, f'{MISSING_FOR_FILECOPY} not built')
class TestFilecopy(unittest.TestCase):
    def setUp(self):
        self.incoming = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.incoming)

        self.source = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.source)

        self.fifo = tempfile.mktemp()
        os.mkfifo(self.fifo)
        self.addCleanup(os.unlink, self.fifo)

    def _local_filecopy(self, *files):
        env = os.environ.copy()
        env['bin'] = BIN
        env['fifo'] = self.fifo
        env['incoming'] = self.incoming

        bash_code = ('trap \'echo PIPESTATUS: ${PIPESTATUS[@]} >&2\' EXIT;'
                     '"$bin"/qfile-agent "$@" <"$fifo" |'
                     'sudo "$bin"/qfile-unpacker $EUID "$incoming" >"$fifo"')
        subprocess_run_diagnosable(
            ['bash', '-euo', 'pipefail', '-c', bash_code, 'bash', *files],
            env=env)

    def test_00_trivial(self):
        fn_rel = 'file'
        fn_abs = os.path.join(self.source, fn_rel)
        fn_dst = os.path.join(self.incoming, fn_rel)
        with open(fn_abs, 'wb'): pass
        self.assertFalse(os.path.exists(fn_dst))
        self._local_filecopy(fn_abs)
        self.assertTrue(os.path.exists(fn_dst))

    def test_10_shadowed_by_mount(self):
        fn_rel = 'file'
        fn_abs = os.path.join(self.source, fn_rel)
        fn_dst = os.path.join(self.incoming, fn_rel)
        with open(fn_abs, 'wb') as f: f.write(b'foo')
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.source)
        subprocess_run_diagnosable(
            ['sudo', 'mount', '-t', 'tmpfs', 'tmpfs', self.source])
        self.addCleanup(subprocess_run_diagnosable,
            ['sudo', 'umount', self.source])
        with open(fn_abs, 'wb') as f: f.write(b'bar')
        with open(fn_abs, 'rb') as f: self.assertEqual(f.read(), b'bar')
        with open(fn_rel, 'rb') as f: self.assertEqual(f.read(), b'foo')
        self.assertFalse(os.path.exists(fn_dst))
        self._local_filecopy(fn_rel)
        with open(fn_dst, 'rb') as f: self.assertEqual(f.read(), b'foo')


def subprocess_run_diagnosable(*args, **kwargs):
    try:
        return subprocess.run(*args, check=True, capture_output=True, **kwargs)
    except subprocess.CalledProcessError as e:
        note = f'stdout={e.stdout!r} stderr={e.stderr!r}'
        #e.add_note(note)  # only available in Python 3.11+
        #raise
        raise Exception(str(e) + ' ' + note) from e
