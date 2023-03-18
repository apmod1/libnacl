
# This notice is included to comply with the terms of the Apache License.
# This file includes portions of code from the original forked __init__.py file.
# The code was modified by Apurva Mody and subsequently placed in this file.

import ctypes
from libnacl import nacl
from libnacl.bindings.constants import (
    crypto_secretbox_KEYBYTES,
    crypto_secretbox_NONCEBYTES,
    crypto_secretbox_MACBYTES,
)

#  Authenticated Symmetric Encryption improved version


def crypto_secretbox_easy(cmessage, nonce, key):
    if len(key) != crypto_secretbox_KEYBYTES:
        raise ValueError("Invalid key")

    if len(nonce) != crypto_secretbox_NONCEBYTES:
        raise ValueError("Invalid nonce")

    ctxt = ctypes.create_string_buffer(
        crypto_secretbox_MACBYTES + len(cmessage))
    ret = nacl.crypto_secretbox_easy(
        ctxt, cmessage, ctypes.c_ulonglong(len(cmessage)), nonce, key
    )
    if ret:
        raise ValueError("Failed to encrypt message")
    return ctxt.raw[0:]


def crypto_secretbox_open_easy(ctxt, nonce, key):
    if len(key) != crypto_secretbox_KEYBYTES:
        raise ValueError("Invalid key")

    if len(nonce) != crypto_secretbox_NONCEBYTES:
        raise ValueError("Invalid nonce")

    msg = ctypes.create_string_buffer(len(ctxt))
    ret = nacl.crypto_secretbox_open_easy(
        msg, ctxt, ctypes.c_ulonglong(len(ctxt)), nonce, key
    )
    if ret:
        raise ValueError("Failed to decrypt message")
    return msg.raw[0: len(ctxt) - crypto_secretbox_MACBYTES]
