#!/usr/bin/env python3
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2026 Jayant Saxena <jayantmcom@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""Unit tests for qubes.GetImageRGBA script.

Tests the fix for QubesOS/qubes-issues#9145: SVG images without explicit
width/height attributes should be converted successfully.
"""

import os
import subprocess
import tempfile
import unittest

SCRIPT_PATH = os.path.join(
    os.path.dirname(__file__), '../qubes-rpc/qubes.GetImageRGBA')

# Minimal SVG with explicit width/height
SVG_WITH_DIMENSIONS = b'''\
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">
  <rect width="10" height="10" fill="#3366cc"/>
</svg>
'''

# SVG with only viewBox, no explicit width/height (reproduces issue #9145)
SVG_WITHOUT_DIMENSIONS = b'''\
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">
  <rect width="10" height="10" fill="#3366cc"/>
</svg>
'''


def _run_script(svg_content):
    """Run qubes.GetImageRGBA with given SVG content, return (returncode, stdout, stderr)."""
    with tempfile.NamedTemporaryFile(suffix='.svg', delete=False) as f:
        f.write(svg_content)
        svg_path = f.name
    try:
        result = subprocess.run(
            [SCRIPT_PATH],
            input=svg_path.encode() + b'\n',
            capture_output=True,
            timeout=10,
        )
        return result.returncode, result.stdout, result.stderr
    finally:
        os.unlink(svg_path)


@unittest.skipUnless(
    os.path.exists(SCRIPT_PATH), 'qubes.GetImageRGBA script not found')
class TestGetImageRGBA(unittest.TestCase):

    def _assert_valid_rgba_output(self, stdout, stderr):
        """Assert stdout contains valid 'W H\\nRGBA_DATA' output."""
        self.assertEqual(b'', stderr, f'Unexpected stderr: {stderr.decode()}')
        lines = stdout.split(b'\n', 1)
        self.assertGreaterEqual(len(lines), 1)
        dims = lines[0].decode().split()
        self.assertEqual(len(dims), 2, f'Expected "W H" on first line, got: {lines[0]}')
        width, height = int(dims[0]), int(dims[1])
        self.assertGreater(width, 0)
        self.assertGreater(height, 0)
        if len(lines) > 1:
            expected = width * height * 4
            self.assertGreaterEqual(len(lines[1]), expected)
        return width, height

    def test_svg_with_explicit_dimensions(self):
        """SVG with explicit width/height should convert successfully."""
        rc, stdout, stderr = _run_script(SVG_WITH_DIMENSIONS)
        self.assertEqual(rc, 0, f'Script failed: {stderr.decode()}')
        self._assert_valid_rgba_output(stdout, b'')

    def test_svg_without_dimensions(self):
        """SVG without explicit width/height (only viewBox) should convert successfully.

        Regression test for QubesOS/qubes-issues#9145.
        """
        rc, stdout, stderr = _run_script(SVG_WITHOUT_DIMENSIONS)
        self.assertEqual(rc, 0, f'Script failed: {stderr.decode()}')
        self._assert_valid_rgba_output(stdout, b'')

    def test_nonexistent_file(self):
        """Non-existent file should cause script to exit with non-zero code."""
        result = subprocess.run(
            [SCRIPT_PATH],
            input=b'/nonexistent/file.svg\n',
            capture_output=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
