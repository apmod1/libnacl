# Import libnacl libs
import libnacl.bindings.authenticated_symmetric_encryption_improved_version as aseiv
import libnacl.high_level.utils

# Import python libs
import unittest


class TestSecret(unittest.TestCase):
    """
    Test secret functions
    """

    def test_secretbox_easy(self):
        msg = b'Are you suggesting coconuts migrate?'

        nonce = libnacl.high_level.utils.rand_nonce()
        key = libnacl.high_level.utils.salsa_key()

        c = aseiv.crypto_secretbox_easy(msg, nonce, key)
        m = aseiv.crypto_secretbox_open_easy(c, nonce, key)
        self.assertEqual(msg, m)

        with self.assertRaises(ValueError):
            aseiv.crypto_secretbox_easy(msg, b'too_short', key)

        with self.assertRaises(ValueError):
            aseiv.crypto_secretbox_easy(msg, nonce, b'too_short')

        with self.assertRaises(ValueError):
            aseiv.crypto_secretbox_open_easy(c, b'too_short', key)

        with self.assertRaises(ValueError):
            aseiv.crypto_secretbox_open_easy(c, nonce, b'too_short')
