# This notice is included to comply with the terms of the Apache License.
# This file includes portions of code from the original forked __init__.py file.
# The code was modified by Apurva Mody and subsequently placed in this file.

import ctypes
from libnacl import nacl
from libnacl.bindings.constants import crypto_generichash_BYTES

#  Generic Hash


def crypto_generichash(msg, key=None):
    """
    Compute the blake2 hash of the given message with a given key
    """
    hbuf = ctypes.create_string_buffer(crypto_generichash_BYTES)
    if key:
        key_len = len(key)
    else:
        key_len = 0
    nacl.crypto_generichash(
        hbuf,
        ctypes.c_size_t(len(hbuf)),
        msg,
        ctypes.c_ulonglong(len(msg)),
        key,
        ctypes.c_size_t(key_len),
    )
    return hbuf.raw
