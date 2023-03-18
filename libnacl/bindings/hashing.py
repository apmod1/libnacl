# This notice is included to comply with the terms of the Apache License.
# This file includes portions of code from the original forked __init__.py file.
# The code was modified by Apurva Mody and subsequently placed in this file.

import ctypes
from libnacl import nacl
from libnacl.bindings.constants import (
    crypto_hash_BYTES,
    crypto_hash_sha256_BYTES,
    crypto_hash_sha512_BYTES,
)

#  Hashing


def crypto_hash(msg):
    """
    Compute a hash of the given message
    """
    hbuf = ctypes.create_string_buffer(crypto_hash_BYTES)
    nacl.crypto_hash(hbuf, msg, ctypes.c_ulonglong(len(msg)))
    return hbuf.raw


def crypto_hash_sha256(msg):
    """
    Compute the sha256 hash of the given message
    """
    hbuf = ctypes.create_string_buffer(crypto_hash_sha256_BYTES)
    nacl.crypto_hash_sha256(hbuf, msg, ctypes.c_ulonglong(len(msg)))
    return hbuf.raw


def crypto_hash_sha512(msg):
    """
    Compute the sha512 hash of the given message
    """
    hbuf = ctypes.create_string_buffer(crypto_hash_sha512_BYTES)
    nacl.crypto_hash_sha512(hbuf, msg, ctypes.c_ulonglong(len(msg)))
    return hbuf.raw
