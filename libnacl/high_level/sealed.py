
import libnacl.high_level.public
import libnacl.high_level.dual
import libnacl.bindings.pubkey_defs as pubkey_defs


class SealedBox(object):
    '''
    Sealed box is a variant of Box that does not authenticate sender.
    '''

    def __init__(self, pk, sk=None):
        self.pk = pk
        self.sk = sk

        if isinstance(pk, (libnacl.high_level.public.SecretKey, libnacl.high_level.dual.DualSecret)):
            self.pk = pk.pk
            self.sk = pk.sk

        if isinstance(pk, libnacl.high_level.public.PublicKey):
            self.pk = pk.pk

    def encrypt(self, msg):
        '''
        Encrypt the given message using the receiver's public key
        '''
        return pubkey_defs.crypto_box_seal(msg, self.pk)

    def decrypt(self, msg):
        '''
        Decrypt the given message using the receiver's public and private key
        '''
        if not self.sk:
            raise ValueError('Secret key is not set')
        return pubkey_defs.crypto_box_seal_open(msg, self.pk, self.sk)
