# This notice is included to comply with the terms of the Apache License.
# The code in this file was modified by Apurva Mody.

# -*- coding: utf-8 -*-
'''
Utilities to make secret box encryption simple
'''
# Import libnacl

import libnacl.high_level.utils
import libnacl.high_level.base
from libnacl.bindings.constants import crypto_aead_chacha20poly1305_ietf_KEYBYTES, crypto_aead_aes256gcm_NPUBBYTES
import libnacl.bindings.authenticated_symmetric_encryption_with_additional_data as asead


class AEAD(libnacl.high_level.base.BaseKey):
    '''
    Manage AEAD encryption using the IETF ChaCha20-Poly1305(default) or AES-GCM algorithm
    '''

    def __init__(self, key=None):
        if key is None:
            key = libnacl.high_level.utils.aead_key()
        if len(key) != crypto_aead_chacha20poly1305_ietf_KEYBYTES:  # same size for both
            raise ValueError('Invalid key')
        self.sk = key
        self.usingAES = False

    def useAESGCM(self):
        self.usingAES = True
        return self

    def encrypt(self, msg, aad, nonce=None, pack_nonce_aad=True):
        '''
        Encrypt the given message. If a nonce is not given it will be
        generated via the rand_nonce function
        '''
        if nonce is None:
            nonce = libnacl.high_level.utils.rand_aead_nonce()
        if len(nonce) != crypto_aead_aes256gcm_NPUBBYTES:
            raise ValueError('Invalid nonce')
        if self.usingAES:
            ctxt = asead.crypto_aead_aes256gcm_encrypt(
                msg, aad, nonce, self.sk)
        else:
            ctxt = asead.crypto_aead_chacha20poly1305_ietf_encrypt(
                msg, aad, nonce, self.sk)

        if pack_nonce_aad:
            return aad + nonce + ctxt
        else:
            return aad, nonce, ctxt

    def decrypt(self, ctxt, aadLen):
        '''
        Decrypt the given message, if no nonce or aad are given they will be
        extracted from the message
        '''
        aad = ctxt[:aadLen]
        nonce = ctxt[aadLen:aadLen +
                     crypto_aead_aes256gcm_NPUBBYTES]
        ctxt = ctxt[aadLen+crypto_aead_aes256gcm_NPUBBYTES:]
        if len(nonce) != crypto_aead_aes256gcm_NPUBBYTES:
            raise ValueError('Invalid nonce')
        if self.usingAES:
            return asead.crypto_aead_aes256gcm_decrypt(ctxt, aad, nonce, self.sk)
        return asead.crypto_aead_chacha20poly1305_ietf_decrypt(ctxt, aad, nonce, self.sk)

    def decrypt_unpacked(self, aad, nonce, ctxt):
        '''
        Decrypt the given message, if no nonce or aad are given they will be
        extracted from the message
        '''
        if len(nonce) != crypto_aead_aes256gcm_NPUBBYTES:
            raise ValueError('Invalid nonce')
        if self.usingAES:
            return asead.crypto_aead_aes256gcm_decrypt(ctxt, aad, nonce, self.sk)
        return asead.crypto_aead_chacha20poly1305_ietf_decrypt(ctxt, aad, nonce, self.sk)
