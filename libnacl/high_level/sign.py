# -*- coding: utf-8 -*-
'''
High level routines to maintain signing keys and to sign and verify messages
'''
# Import libancl libs

import libnacl.high_level.base
import libnacl.high_level.encode
from libnacl.bindings.constants import crypto_sign_SEEDBYTES, crypto_sign_BYTES
import libnacl.bindings.signing_functions as sf
import libnacl.bindings.random_byte_generation as rbg


class Signer(libnacl.high_level.base.BaseKey):
    '''
    The tools needed to sign messages
    '''

    def __init__(self, seed=None):
        '''
        Create a signing key, if not seed it supplied a keypair is generated
        '''
        if seed:
            if len(seed) != crypto_sign_SEEDBYTES:
                raise ValueError('Invalid seed bytes')
            self.vk, self.sk = sf.crypto_sign_seed_keypair(seed)
        else:
            seed = rbg.randombytes(
                crypto_sign_SEEDBYTES)
            self.vk, self.sk = sf.crypto_sign_seed_keypair(
                seed)
        self.seed = seed

    def sign(self, msg):
        '''
        Sign the given message with this key
        '''
        return sf.crypto_sign(msg, self.sk)

    def signature(self, msg):
        '''
        Return just the signature for the message
        '''
        return sf.crypto_sign(msg, self.sk)[:crypto_sign_BYTES]


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
        return sf.crypto_sign_open(msg, self.vk)
