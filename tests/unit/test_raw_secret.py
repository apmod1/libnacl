# This notice is included to comply with the terms of the Apache License.
# The code in this file was modified by Apurva Mody.

# Import libnacl libs
import libnacl.bindings.authenticated_symmetric_encryption as ase
import libnacl.high_level.utils

# Import python libs
import unittest


class TestSecret(unittest.TestCase):
    """
    Test secret functions
    """

    def test_secretbox(self):
        msg = b'Are you suggesting coconuts migrate?'

        nonce = libnacl.high_level.utils.rand_nonce()
        key = libnacl.high_level.utils.salsa_key()

        c = ase.crypto_secretbox(msg, nonce, key)
        m = ase.crypto_secretbox_open(c, nonce, key)
        self.assertEqual(msg, m)

        with self.assertRaises(ValueError):
            ase.crypto_secretbox(msg, b'too_short', key)

        with self.assertRaises(ValueError):
            ase.crypto_secretbox(msg, nonce, b'too_short')

        with self.assertRaises(ValueError):
            ase.crypto_secretbox_open(c, b'too_short', key)

        with self.assertRaises(ValueError):
            ase.crypto_secretbox_open(c, nonce, b'too_short')
