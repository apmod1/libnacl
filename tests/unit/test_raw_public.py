# Import libnacl libs
import libnacl.bindings.pubkey_defs as pubkey_defs
import libnacl.high_level.utils
from libnacl.bindings.constants import crypto_box_PUBLICKEYBYTES
# Import python libs
import unittest


class TestPublic(unittest.TestCase):
    '''
    Test public functions
    '''

    def test_gen(self):
        pk1, sk1 = pubkey_defs.crypto_box_keypair()
        pk2, sk2 = pubkey_defs.crypto_box_keypair()
        pk3, sk3 = pubkey_defs.crypto_box_keypair()
        self.assertEqual(len(pk1), crypto_box_PUBLICKEYBYTES)
        self.assertEqual(len(sk1), crypto_box_PUBLICKEYBYTES)
        self.assertEqual(len(pk2), crypto_box_PUBLICKEYBYTES)
        self.assertEqual(len(sk2), crypto_box_PUBLICKEYBYTES)
        self.assertEqual(len(pk3), crypto_box_PUBLICKEYBYTES)
        self.assertEqual(len(sk3), crypto_box_PUBLICKEYBYTES)
        self.assertNotEqual(pk1, sk1)
        self.assertNotEqual(pk2, sk2)
        self.assertNotEqual(pk3, sk3)
        self.assertNotEqual(pk1, pk2)
        self.assertNotEqual(pk1, pk3)
        self.assertNotEqual(sk1, sk2)
        self.assertNotEqual(sk2, sk3)

    def test_box(self):
        msg = b'Are you suggesting coconuts migrate?'
        # run 1
        nonce1 = libnacl.high_level.utils.rand_nonce()
        pk1, sk1 = pubkey_defs.crypto_box_keypair()
        pk2, sk2 = pubkey_defs.crypto_box_keypair()
        enc_msg = pubkey_defs.crypto_box(msg, nonce1, pk2, sk1)
        self.assertNotEqual(msg, enc_msg)
        clear_msg = pubkey_defs.crypto_box_open(enc_msg, nonce1, pk1, sk2)
        self.assertEqual(clear_msg, msg)
        # run 2
        nonce2 = libnacl.high_level.utils.rand_nonce()
        pk3, sk3 = pubkey_defs.crypto_box_keypair()
        pk4, sk4 = pubkey_defs.crypto_box_keypair()
        enc_msg2 = pubkey_defs.crypto_box(msg, nonce2, pk4, sk3)
        self.assertNotEqual(msg, enc_msg2)
        clear_msg2 = pubkey_defs.crypto_box_open(enc_msg2, nonce2, pk3, sk4)
        self.assertEqual(clear_msg2, msg)
        # Check bits
        self.assertNotEqual(nonce1, nonce2)
        self.assertNotEqual(enc_msg, enc_msg2)

    def test_boxnm(self):
        msg = b'Are you suggesting coconuts migrate?'
        # run 1
        nonce1 = libnacl.high_level.utils.rand_nonce()
        pk1, sk1 = pubkey_defs.crypto_box_keypair()
        pk2, sk2 = pubkey_defs.crypto_box_keypair()
        k1 = pubkey_defs.crypto_box_beforenm(pk2, sk1)
        k2 = pubkey_defs.crypto_box_beforenm(pk1, sk2)
        enc_msg = pubkey_defs.crypto_box_afternm(msg, nonce1, k1)
        self.assertNotEqual(msg, enc_msg)
        clear_msg = pubkey_defs.crypto_box_open_afternm(enc_msg, nonce1, k2)
        self.assertEqual(clear_msg, msg)

    def test_box_seal(self):
        msg = b'Are you suggesting coconuts migrate?'
        # run 1
        pk, sk = pubkey_defs.crypto_box_keypair()
        enc_msg = pubkey_defs.crypto_box_seal(msg, pk)
        self.assertNotEqual(msg, enc_msg)
        clear_msg = pubkey_defs.crypto_box_seal_open(enc_msg, pk, sk)
        self.assertEqual(clear_msg, msg)
        # run 2
        pk2, sk2 = pubkey_defs.crypto_box_keypair()
        enc_msg2 = pubkey_defs.crypto_box_seal(msg, pk2)
        self.assertNotEqual(msg, enc_msg2)
        clear_msg2 = pubkey_defs.crypto_box_seal_open(enc_msg2, pk2, sk2)
        self.assertEqual(clear_msg2, msg)
        # Check bits
        self.assertNotEqual(enc_msg, enc_msg2)

    def test_scalarmult_rejects_wrong_length(self):
        good_key = b'This valid key is 32 bytes long.'

        for bad_key in (b'too short', b'too long' * 100):
            with self.assertRaises(ValueError) as context:
                pubkey_defs.crypto_scalarmult_base(bad_key)
            self.assertEqual(context.exception.args, ('Invalid secret key',))

        self.assertEqual(crypto_box_PUBLICKEYBYTES, len(
            pubkey_defs.crypto_scalarmult_base(good_key)))
