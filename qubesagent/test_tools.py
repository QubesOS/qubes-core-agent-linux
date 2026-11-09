import errno
import json
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

# Plays qfile-conflict-dialog: runs qfile-unpacker, answers its conflict
# requests in order, and saves the requests as JSON.
CONFLICT_RESPONDER = r'''
import json, os, socket, subprocess, sys
requests_path, answers, unpacker = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3:]
ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
proc = subprocess.Popen(
    [unpacker[0], f"--conflict-fd={theirs.fileno()}"] + unpacker[1:],
    pass_fds=(theirs.fileno(),))
theirs.close()
null = os.open(os.devnull, os.O_RDWR)
os.dup2(null, 0)
os.dup2(null, 1)
requests = []
while True:
    request = ours.recv(65536)
    if not request:
        break
    requests.append(request.decode().split("\0")[:4])
    ours.send(answers.pop(0).encode() if answers else b"a")
ours.close()
with open(requests_path, "w") as f:
    json.dump(requests, f)
sys.exit(proc.wait())
'''

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

    def _conflict_filecopy(self, answers, *files):
        """Copy files, answering conflicts with answers ("o", "s", "a" or
        "r\\0NAME"). Returns (agent exit code, unpacker exit code,
        unpacker stderr, requests)."""
        requests_path = os.path.join(self.source, '.requests')
        env = os.environ.copy()
        env.update(bin=BIN, fifo=self.fifo, incoming=self.incoming,
                   responder=CONFLICT_RESPONDER, requests=requests_path,
                   answers=json.dumps(answers))
        bash_code = ('trap \'echo PIPESTATUS: ${PIPESTATUS[@]} >&2\' EXIT;'
                     '"$bin"/qfile-agent "$@" <"$fifo" |'
                     'sudo python3 -c "$responder" "$requests" "$answers" '
                     '"$bin"/qfile-unpacker $EUID "$incoming" >"$fifo"')
        proc = subprocess.run(['bash', '-uo', 'pipefail', '-c', bash_code,
                               'bash', *files],
                              env=env, capture_output=True, text=True,
                              cwd=self.source)
        status = proc.stderr.rsplit('PIPESTATUS:', 1)[1].split()
        with open(requests_path) as f:
            requests = json.load(f)
        os.unlink(requests_path)
        return int(status[0]), int(status[1]), proc.stderr, requests

    def _write(self, directory, name, content):
        path = os.path.join(directory, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(content)

    def _read(self, name):
        with open(os.path.join(self.incoming, name)) as f:
            return f.read()

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

    def test_20_conflict_no_handler(self):
        self._write(self.source, 'a', 'new')
        self._write(self.incoming, 'a', 'old')
        env = os.environ.copy()
        env.update(bin=BIN, fifo=self.fifo, incoming=self.incoming)
        proc = subprocess.run(
            ['bash', '-uo', 'pipefail', '-c',
             '"$bin"/qfile-agent a <"$fifo" |'
             'sudo "$bin"/qfile-unpacker $EUID "$incoming" >"$fifo";'
             'echo "PIPESTATUS: ${PIPESTATUS[@]}" >&2'],
            env=env, capture_output=True, text=True, cwd=self.source)
        self.assertIn(f'PIPESTATUS: 1 {errno.EEXIST}', proc.stderr)
        self.assertEqual(self._read('a'), 'old')

    def test_21_conflict_overwrite(self):
        self._write(self.source, 'a', 'new')
        self._write(self.source, 'b', 'new b')
        self._write(self.incoming, 'a', 'old')
        agent, unpacker, stderr, requests = self._conflict_filecopy(
            ['o'], 'a', 'b')
        self.assertEqual((agent, unpacker), (0, 0), stderr)
        self.assertEqual(requests, [['1', 'a', 'a_1', '']])
        self.assertIn('a: replaced the existing file', stderr)
        self.assertEqual(self._read('a'), 'new')
        self.assertEqual(self._read('b'), 'new b')
        self.assertEqual(sorted(os.listdir(self.incoming)), ['a', 'b'])

    def test_22_conflict_skip(self):
        self._write(self.source, 'a', 'new')
        self._write(self.source, 'b', 'new b')
        self._write(self.incoming, 'a', 'old')
        agent, unpacker, stderr, _ = self._conflict_filecopy(['s'], 'a', 'b')
        self.assertEqual((agent, unpacker), (1, errno.ECANCELED), stderr)
        self.assertIn('Some files were not copied', stderr)
        self.assertEqual(self._read('a'), 'old')
        self.assertEqual(self._read('b'), 'new b')

    def test_23_conflict_rename(self):
        self._write(self.source, 'a.tar.gz', 'new')
        self._write(self.incoming, 'a.tar.gz', 'old')
        self._write(self.incoming, 'taken', 'other')
        agent, unpacker, stderr, requests = self._conflict_filecopy(
            ['r\0taken', 'r\0../x', 'r\0new'], 'a.tar.gz')
        self.assertEqual((agent, unpacker), (0, 0), stderr)
        self.assertEqual(requests, [
            ['1', 'a.tar.gz', 'a_1.tar.gz', ''],
            ['1', 'a.tar.gz', 'taken',
             'A file with this name already exists too.'],
            ['1', 'a.tar.gz', '../x', 'Invalid name.'],
        ])
        self.assertEqual(self._read('a.tar.gz'), 'old')
        self.assertEqual(self._read('new'), 'new')

    def test_24_conflict_abort(self):
        self._write(self.source, 'a', 'new')
        self._write(self.incoming, 'a', 'old')
        agent, unpacker, stderr, _ = self._conflict_filecopy(['a'], 'a')
        self.assertEqual((agent, unpacker), (1, errno.EEXIST), stderr)
        self.assertEqual(self._read('a'), 'old')

    def test_25_conflict_symlink(self):
        self._write(self.source, 'd/target', 'new')
        os.symlink('target', os.path.join(self.source, 'd', 'link'))
        self._write(self.incoming, 'd/target', 'old')
        os.symlink('other', os.path.join(self.incoming, 'd', 'link'))
        agent, unpacker, stderr, requests = self._conflict_filecopy(
            ['o', 'o'], 'd')
        self.assertEqual((agent, unpacker), (0, 0), stderr)
        self.assertEqual(len(requests), 2)
        self.assertEqual(
            os.readlink(os.path.join(self.incoming, 'd', 'link')), 'target')
        self.assertEqual(self._read('d/target'), 'new')

    def test_26_conflict_directory_in_the_way(self):
        self._write(self.source, 'a', 'new')
        os.mkdir(os.path.join(self.incoming, 'a'))
        agent, unpacker, stderr, requests = self._conflict_filecopy(
            ['o', 's'], 'a')
        self.assertEqual((agent, unpacker), (1, errno.ECANCELED), stderr)
        self.assertEqual(requests, [
            ['0', 'a', 'a_1', ''],
            ['0', 'a', 'a_1', 'A directory cannot be replaced by a file.'],
        ])
        self.assertTrue(os.path.isdir(os.path.join(self.incoming, 'a')))


def subprocess_run_diagnosable(*args, **kwargs):
    try:
        return subprocess.run(*args, check=True, capture_output=True, **kwargs)
    except subprocess.CalledProcessError as e:
        note = f'stdout={e.stdout!r} stderr={e.stderr!r}'
        #e.add_note(note)  # only available in Python 3.11+
        #raise
        raise Exception(str(e) + ' ' + note) from e
