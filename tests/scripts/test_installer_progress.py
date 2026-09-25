#!/usr/bin/env python3
"""Regression: a live installer must show new ACME stages on its TTY."""

import errno
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
INSTALLERS = (
    ROOT / 'scripts/install.sh',
    ROOT / 'scripts/install-offline.sh',
    ROOT / 'offline-bundle/install.sh',
)


class InstallerProgressTest(unittest.TestCase):
    def test_interactive_controller_choice(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / 'hyperdns'
            binary.write_text('#!/bin/sh\nprintf "  -role string\\n"\n')
            binary.chmod(0o755)
            for installer in INSTALLERS:
                with self.subTest(installer=installer.name):
                    source = installer.read_text()
                    start = source.index('# Helper for reading user input cleanly')
                    end = source.index('install -d -o root -g root -m 0755 "${INSTALL_DIR}"', start)
                    setup = source[start:end]
                    master, slave = os.openpty()
                    try:
                        process = subprocess.Popen(
                            ['bash', '-c', f'SRC_BIN={binary}\n' + setup],
                            stdin=slave, stdout=slave, stderr=slave,
                        )
                        os.write(master, b'y\n')
                        self.assertEqual(process.wait(timeout=3), 0)
                        output = os.read(master, 65536)
                        self.assertIn(b'Install role: controller', output)
                    finally:
                        os.close(master)
                        os.close(slave)

    def test_spinner_stage_reaches_terminal(self):
        for installer in INSTALLERS:
            with self.subTest(installer=installer.name):
                source = installer.read_text()
                start = source.index('SPINNER_PID=""')
                end = source.index('# Progress spinner functions end here.', start)
                functions = source[start:end]
                master, slave = os.openpty()
                try:
                    process = subprocess.Popen(
                        ['bash', '-c', functions + '\nspinner_start "initial stage"\n'
                         'sleep 0.4\nspinner_msg "updated stage"\n'
                         'sleep 0.4\nspinner_stop\n'],
                        stdin=subprocess.DEVNULL, stdout=slave, stderr=slave,
                    )
                    os.close(slave)
                    slave = -1
                    output = bytearray()
                    deadline = time.monotonic() + 5
                    while process.poll() is None and time.monotonic() < deadline:
                        if select.select([master], [], [], 1)[0]:
                            try:
                                chunk = os.read(master, 65536)
                                if chunk:
                                    output.extend(chunk)
                            except OSError as exc:
                                if exc.errno != errno.EIO:
                                    raise
                    if process.poll() is None:
                        process.kill()
                        self.fail('spinner did not stop')
                    while select.select([master], [], [], 0)[0]:
                        try:
                            chunk = os.read(master, 65536)
                            if not chunk:
                                break
                            output.extend(chunk)
                        except OSError as exc:
                            if exc.errno != errno.EIO:
                                raise
                            break
                    self.assertEqual(process.returncode, 0)
                    self.assertIn(b'initial stage', output)
                    self.assertIn(b'updated stage', output)
                finally:
                    os.close(master)
                    if slave >= 0:
                        os.close(slave)


if __name__ == '__main__':
    unittest.main()
