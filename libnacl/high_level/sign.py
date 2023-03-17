# -*- coding: utf-8 -*-
'''
High level routines to maintain signing keys and to sign and verify messages
'''
# Import libancl libs
import libnacl
import libnacl.high_level.base
import libnacl.high_level.encode


class Signer(libnacl.high_level.base.BaseKey):
    '''
    The tools needed to sign messages
    '''
    def __init__(self, seed=None):
        '''
        Create a signing key, if not seed it supplied a keypair is generated
        '''
        if seed:
            if len(seed) != libnacl.high_level.crypto_sign_SEEDBYTES:
                raise ValueError('Invalid seed bytes')
            self.vk, self.sk = libnacl.high_level.crypto_sign_seed_keypair(seed)
        else:
            seed = libnacl.high_level.randombytes(libnacl.high_level.crypto_sign_SEEDBYTES)
            self.vk, self.sk = libnacl.high_level.crypto_sign_seed_keypair(seed)
        self.seed = seed

    def sign(self, msg):
        '''
        Sign the given message with this key
        '''
        return libnacl.high_level.crypto_sign(msg, self.sk)

    def signature(self, msg):
        '''
        Return just the signature for the message
        '''
        return libnacl.high_level.crypto_sign(msg, self.sk)[:libnacl.high_level.crypto_sign_BYTES]


class Verifier(libnacl.high_level.base.BaseKey):
    '''
    Verify signed messages
    '''
    def __init__(self, vk_hex):
        '''
        Create a verification key from a hex encoded vkey
        '''
        self.vk = libnacl.high_level.encode.hex_decode(vk_hex)

    def verify(self, msg):
        '''
        Verify the message with tis key
        '''
        return libnacl.high_level.crypto_sign_open(msg, self.vk)
