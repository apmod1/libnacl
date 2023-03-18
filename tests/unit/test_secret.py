# This notice is included to comply with the terms of the Apache License.
# The code in this file was modified by Apurva Mody.

# Import libnacl libs
import libnacl.high_level.secret
# Import python libs
import unittest


class TestSecret(unittest.TestCase):
    '''
    '''

    def test_secret(self):
        msg = b'But then of course African swallows are not migratory.'
        box = libnacl.high_level.secret.SecretBox()
        ctxt = box.encrypt(msg)
        self.assertNotEqual(msg, ctxt)
        box2 = libnacl.high_level.secret.SecretBox(box.sk)
        clear1 = box.decrypt(ctxt)
        self.assertEqual(msg, clear1)
        clear2 = box2.decrypt(ctxt)
        self.assertEqual(clear1, clear2)
        ctxt2 = box2.encrypt(msg)
        clear3 = box.decrypt(ctxt2)
        self.assertEqual(clear3, msg)
