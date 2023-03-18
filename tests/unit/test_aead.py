# This notice is included to comply with the terms of the Apache License.
# The code in this file was modified by Apurva Mody.

# Import libnacl libs
import libnacl.high_level.aead
# Import python libs
import unittest
from libnacl.bindings.constants import HAS_AEAD_AES256GCM, HAS_AEAD_CHACHA20POLY1305_IETF


class TestAEAD(unittest.TestCase):
    '''
    '''
    @unittest.skipUnless(HAS_AEAD_AES256GCM, 'AES256-GCM AEAD not available')
    def test_gcm_aead(self):
        msg = b"You've got two empty halves of coconuts and your bangin' 'em together."
        aad = b'\x00\x11\x22\x33'
        box = libnacl.high_level.aead.AEAD().useAESGCM()
        ctxt = box.encrypt(msg, aad)
        self.assertNotEqual(msg, ctxt)

        box2 = libnacl.high_level.aead.AEAD(box.sk).useAESGCM()
        clear1 = box.decrypt(ctxt, len(aad))
        self.assertEqual(msg, clear1)
        clear2 = box2.decrypt(ctxt, len(aad))
        self.assertEqual(clear1, clear2)
        ctxt2 = box2.encrypt(msg, aad)
        clear3 = box.decrypt(ctxt2, len(aad))
        self.assertEqual(clear3, msg)

    @unittest.skipUnless(HAS_AEAD_CHACHA20POLY1305_IETF, 'IETF variant of ChaCha20Poly1305 AEAD not available')
    def test_ietf_aead(self):
        msg = b"Our King? Well i didn't vote for you!!"
        aad = b'\x00\x11\x22\x33'
        box = libnacl.high_level.aead.AEAD()
        ctxt = box.encrypt(msg, aad)
        self.assertNotEqual(msg, ctxt)

        box2 = libnacl.high_level.aead.AEAD(box.sk)
        clear1 = box.decrypt(ctxt, len(aad))
        self.assertEqual(msg, clear1)
        clear2 = box2.decrypt(ctxt, len(aad))
        self.assertEqual(clear1, clear2)
        ctxt2 = box2.encrypt(msg, aad)
        clear3 = box.decrypt(ctxt2, len(aad))
        self.assertEqual(clear3, msg)
