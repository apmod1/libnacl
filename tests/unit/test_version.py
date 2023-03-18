# This notice is included to comply with the terms of the Apache License.
# The code in this file was modified by Apurva Mody.

"""
Basic tests for version functions
"""

import libnacl.bindings.utility_functions as uf
import unittest


# These are copied from libsodium test suite
class TestSodiumVersion(unittest.TestCase):
    def test_version_string(self):
        self.assertIsNotNone(uf.sodium_version_string())

    def test_library_version_major(self):
        # Using assertTrue to keep tests "uniform" and keep compatibility with
        # Python 2.6
        self.assertTrue(uf.sodium_library_version_major() > 0)

    def test_library_version_minor(self):
        # Using assertTrue to keep tests "uniform" and keep compatibility with
        # Python 2.6 (assertGreaterEqual appeared in Python 2.7 only)
        self.assertTrue(uf.sodium_library_version_minor() >= 0)
