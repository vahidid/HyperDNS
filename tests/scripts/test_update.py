#!/usr/bin/env python3
"""Exercise update.sh success and rollback against a disposable install tree."""

import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class UpdateScriptTest(unittest.TestCase):
    def run_update(self, failing: bool) -> tuple[subprocess.CompletedProcess[str], Path, Path, bytes]:
        workspace = Path(tempfile.mkdtemp(prefix='hyperdns-update-test-'))
        self.addCleanup(shutil.rmtree, workspace)
        install = workspace / 'hyperdns'
        install.mkdir()
        (install / 'data.db').write_bytes(b'original database')
        (install / 'master.key').write_bytes(b'original key')
        (install / 'version.json').write_text('{"version":"old"}\n')
        old = b'#!/bin/sh\n[ "$1" = -version ] && echo old\n'
        (install / 'hyperdns').write_bytes(old)
        (install / 'hyperdns').chmod(0o755)
        new = workspace / 'new-binary'
        new.write_text('#!/bin/sh\n[ "$1" = -version ] && echo new\n' + ('# FAIL_ON_START\n' if failing else ''))
        new.chmod(0o755)
        version = workspace / 'version.json'
        version.write_text('{"version":"new"}\n')

        source = (ROOT / 'scripts/update.sh').read_text()
        source = source.replace('INSTALL_DIR=/opt/hyperdns', f'INSTALL_DIR={install}')
        source = source.replace('BACKUP_ROOT=/root/hyperdns-update-backups', f'BACKUP_ROOT={workspace / "backups"}')
        source = source.replace('tar -C /opt ', f'tar -C {workspace} ')
        self.assertNotIn('tar -C /opt ', source)
        script = workspace / 'update.sh'
        script.write_text(source)

        stubs = workspace / 'stubs'
        stubs.mkdir()
        for name, body in {
            'id': '#!/bin/sh\necho 0\n',
            'stat': '#!/bin/sh\necho 0\n',
            'sleep': '#!/bin/sh\nexit 0\n',
            'readlink': '#!/usr/bin/env python3\nimport os,sys\nprint(os.path.realpath(sys.argv[-1]))\n',
            'sha256sum': '#!/usr/bin/env python3\nimport hashlib,sys\np=sys.argv[-1]\nprint(hashlib.sha256(open(p,"rb").read()).hexdigest(),p)\n',
        }.items():
            path = stubs / name
            path.write_text(body)
            path.chmod(0o755)

        systemctl = stubs / 'systemctl'
        systemctl.write_text('''#!/usr/bin/env python3
import os, pathlib, sys
base = pathlib.Path(os.environ['TEST_ROOT'])
args = sys.argv[1:]
state = base / 'service.state'
pid = base / 'service.pid'
binary = (base / 'hyperdns/hyperdns').read_text()
if args[0] == 'cat':
    print('ExecStart=/opt/hyperdns/hyperdns -daemon -role controller')
elif args[:2] == ['is-active', '--quiet']:
    sys.exit(0 if state.read_text() == 'active' else 3)
elif args[0] == 'stop':
    state.write_text('stopped')
elif args[0] == 'start':
    if 'FAIL_ON_START' in binary:
        (base / 'hyperdns/data.db').write_bytes(b'changed by failed binary')
        state.write_text('failed')
        sys.exit(1)
    pid.write_text(str(int(pid.read_text()) + 1))
    state.write_text('active')
elif args[0] == 'show':
    print(pid.read_text())
elif args[:3] == ['--no-pager', '--full', 'status']:
    print('active')
else:
    sys.exit(97)
''')
        systemctl.chmod(0o755)
        (workspace / 'service.state').write_text('active')
        (workspace / 'service.pid').write_text('100')

        env = dict(os.environ, PATH=f'{stubs}:{os.environ["PATH"]}', TEST_ROOT=str(workspace))
        result = subprocess.run(['bash', str(script), 'hyperdns', str(new), str(version)],
                                env=env, text=True, capture_output=True, timeout=20)
        return result, workspace, install, old

    def test_success_keeps_state_and_retains_complete_backup(self):
        result, workspace, install, old = self.run_update(False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('echo new', (install / 'hyperdns').read_text())
        self.assertEqual((install / 'data.db').read_bytes(), b'original database')
        self.assertEqual((install / 'master.key').read_bytes(), b'original key')
        self.assertIn('"new"', (install / 'version.json').read_text())
        archive, = (workspace / 'backups').glob('*/install.tar.gz')
        with tarfile.open(archive) as saved:
            self.assertEqual(saved.extractfile('hyperdns/hyperdns').read(), old)
            self.assertEqual(saved.extractfile('hyperdns/data.db').read(), b'original database')
        self.assertEqual((workspace / 'service.state').read_text(), 'active')

    def test_failed_start_restores_binary_database_and_version(self):
        result, workspace, install, old = self.run_update(True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((install / 'hyperdns').read_bytes(), old)
        self.assertEqual((install / 'data.db').read_bytes(), b'original database')
        self.assertEqual((install / 'master.key').read_bytes(), b'original key')
        self.assertIn('"old"', (install / 'version.json').read_text())
        self.assertEqual((workspace / 'service.state').read_text(), 'active')


if __name__ == '__main__':
    unittest.main()
