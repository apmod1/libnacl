# This notice is included to comply with the terms of the Apache License.
# This file includes portions of code from the original forked __init__.py file.
# The code was modified by Apurva Mody and subsequently placed in this file.

import ctypes
from libnacl import nacl
from libnacl.bindings.constants import HAS_CRYPT_KDF, crypto_kdf_KEYBYTES

#  Key derivation API


def crypto_kdf_keygen():
    """
    Returns a string of random bytes to generate a master key
    """
    if not HAS_CRYPT_KDF:
        raise ValueError(
            "Underlying Sodium library does not support crypto_kdf_keybytes"
        )
    size = crypto_kdf_KEYBYTES
    buf = ctypes.create_string_buffer(size)
    nacl.crypto_kdf_keygen(buf)
    return buf.raw


def crypto_kdf_derive_from_key(subkey_size, subkey_id, context, master_key):
    """
    Returns a subkey generated from a master key for a given subkey_id.
    For a given subkey_id, the subkey will always be the same string.
    """
    size = int(subkey_size)
    buf = ctypes.create_string_buffer(size)
    nacl.crypto_kdf_derive_from_key(
        buf, subkey_size, ctypes.c_ulonglong(subkey_id), context, master_key
    )
    return buf.raw
