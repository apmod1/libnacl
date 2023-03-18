# This notice is included to comply with the terms of the Apache License.
# The code in this file was modified by Apurva Mody.

# Import nacl libs
import libnacl
import libnacl.high_level.utils
import libnacl.bindings.authenticated_symmetric_encryption_improved_version as aseiv
# Import python libs
import unittest


class TestSecretBox(unittest.TestCase):
    '''
    Test sign functions
    '''

    def test_secret_box_easy(self):
        msg = b'Are you suggesting coconuts migrate?'
        sk1 = libnacl.high_level.utils.salsa_key()
        nonce1 = libnacl.high_level.utils.rand_nonce()
        enc_msg = aseiv.crypto_secretbox_easy(msg, nonce1, sk1)
        self.assertNotEqual(msg, enc_msg)
        clear_msg = aseiv.crypto_secretbox_open_easy(enc_msg, nonce1, sk1)
        self.assertEqual(msg, clear_msg)
