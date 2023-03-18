# This notice is included to comply with the terms of the Apache License.
# The code in this file was modified by Apurva Mody.

# -*- coding: utf-8 -*-
'''
Utilities to make secret box encryption simple
'''
# Import libnacl

import libnacl.high_level.utils
import libnacl.high_level.base
from libnacl.bindings.constants import crypto_secretbox_KEYBYTES, crypto_secretbox_NONCEBYTES
import libnacl.bindings.authenticated_symmetric_encryption as ase


class SecretBox(libnacl.high_level.base.BaseKey):
    '''
    Manage symetric encryption using the salsa20 algorithm
    '''

    def __init__(self, key=None):
        if key is None:
            key = libnacl.high_level.utils.salsa_key()
        if len(key) != crypto_secretbox_KEYBYTES:
            raise ValueError('Invalid key')
        self.sk = key

    def encrypt(self, msg, nonce=None, pack_nonce=True):
        '''
        Encrypt the given message. If a nonce is not given it will be
        generated via the rand_nonce function
        '''
        if nonce is None:
            nonce = libnacl.high_level.utils.rand_nonce()
        if len(nonce) != crypto_secretbox_NONCEBYTES:
            raise ValueError('Invalid nonce size')
        ctxt = ase.crypto_secretbox(msg, nonce, self.sk)
        if pack_nonce:
            return nonce + ctxt
        else:
            return nonce, ctxt

    def decrypt(self, ctxt, nonce=None):
        '''
        Decrypt the given message, if no nonce is given the nonce will be
        extracted from the message
        '''
        if nonce is None:
            nonce = ctxt[:crypto_secretbox_NONCEBYTES]
            ctxt = ctxt[crypto_secretbox_NONCEBYTES:]
        if len(nonce) != crypto_secretbox_NONCEBYTES:
            raise ValueError('Invalid nonce')
        return ase.crypto_secretbox_open(ctxt, nonce, self.sk)
