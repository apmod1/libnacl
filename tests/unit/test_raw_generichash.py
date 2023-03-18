# This notice is included to comply with the terms of the Apache License.
# The code in this file was modified by Apurva Mody.

# Import nacl libs
import libnacl.bindings.generic_hash as gh
import libnacl.high_level.utils
# Import python libs
import unittest


class TestGenericHash(unittest.TestCase):
    '''
    Test sign functions
    '''

    def test_keyless_generichash(self):
        msg1 = b'Are you suggesting coconuts migrate?'
        msg2 = b'Not at all, they could be carried.'
        chash1 = gh.crypto_generichash(msg1)
        chash2 = gh.crypto_generichash(msg2)
        self.assertNotEqual(msg1, chash1)
        self.assertNotEqual(msg2, chash2)
        self.assertNotEqual(chash2, chash1)

    def test_key_generichash(self):
        msg1 = b'Are you suggesting coconuts migrate?'
        msg2 = b'Not at all, they could be carried.'
        key1 = libnacl.high_level.utils.rand_nonce()
        key2 = libnacl.high_level.utils.rand_nonce()
        khash1_1 = gh.crypto_generichash(msg1, key1)
        khash1_1_2 = gh.crypto_generichash(msg1, key1)
        khash1_2 = gh.crypto_generichash(msg1, key2)
        khash2_1 = gh.crypto_generichash(msg2, key1)
        khash2_2 = gh.crypto_generichash(msg2, key2)
        self.assertNotEqual(msg1, khash1_1)
        self.assertNotEqual(msg1, khash1_2)
        self.assertNotEqual(msg2, khash2_1)
        self.assertNotEqual(msg2, khash2_2)
        self.assertNotEqual(khash1_1, khash1_2)
        self.assertNotEqual(khash2_1, khash2_2)
        self.assertNotEqual(khash1_1, khash2_1)
        self.assertNotEqual(khash1_2, khash2_2)
        self.assertEqual(khash1_1, khash1_1_2)
