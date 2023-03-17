'''
The dual key system allows for the creation of keypairs that contain both
cryptographic and signing keys
'''
# import libnacl libs

import libnacl.high_level.base
import libnacl.high_level.public
import libnacl.high_level.sign


class DualSecret(libnacl.high_level.base.BaseKey):
    '''
    Manage crypt and sign keys in one object
    '''

    def __init__(self, crypt=None, sign=None):
        self.crypt = libnacl.high_level.public.SecretKey(crypt)
        self.signer = libnacl.high_level.sign.Signer(sign)
        self.sk = self.crypt.sk
        self.seed = self.signer.seed
        self.pk = self.crypt.pk
        self.vk = self.signer.vk

    def sign(self, msg):
        '''
        Sign the given message
        '''
        return self.signer.sign(msg)

    def signature(self, msg):
        '''
        Return just the signature for the message
        '''
        return self.signer.signature(msg)
