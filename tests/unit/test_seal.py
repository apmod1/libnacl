# This notice is included to comply with the terms of the Apache License.
# The code in this file was modified by Apurva Mody.

# Import libnacl libs
import libnacl.high_level.sealed
import libnacl.high_level.public

# Import python libs
import unittest


class TestSealed(unittest.TestCase):
    '''
    '''

    def test_secretkey(self):
        '''
        '''
        msg = b'You\'ve got two empty halves of coconut and you\'re bangin\' \'em together.'
        key = libnacl.high_level.public.SecretKey()
        box = libnacl.high_level.sealed.SealedBox(key)
        ctxt = box.encrypt(msg)
        self.assertNotEqual(msg, ctxt)
        bclear = box.decrypt(ctxt)
        self.assertEqual(msg, bclear)

    def test_publickey_only(self):
        '''
        '''
        msg = b'You\'ve got two empty halves of coconut and you\'re bangin\' \'em together.'
        key = libnacl.high_level.public.SecretKey()
        key_public = libnacl.high_level.public.PublicKey(key.pk)

        box = libnacl.high_level.sealed.SealedBox(key_public)
        ctxt = box.encrypt(msg)
        self.assertNotEqual(msg, ctxt)

        decrypting_box = libnacl.high_level.sealed.SealedBox(key)
        bclear = decrypting_box.decrypt(ctxt)
        self.assertEqual(msg, bclear)
