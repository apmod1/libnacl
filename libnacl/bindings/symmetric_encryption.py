# This notice is included to comply with the terms of the Apache License.
# This file includes portions of code from the original forked __init__.py file.
# The code was modified by Apurva Mody and subsequently placed in this file.

import ctypes
from libnacl import nacl
from libnacl.bindings.constants import crypto_stream_KEYBYTES, crypto_stream_NONCEBYTES

#  Symmetric Encryption


def crypto_stream(slen, nonce, key):
    """
    Generates a stream using the given secret key and nonce
    """
    if len(key) != crypto_stream_KEYBYTES:
        raise ValueError("Invalid secret key")
    if len(nonce) != crypto_stream_NONCEBYTES:
        raise ValueError("Invalid nonce")

    stream = ctypes.create_string_buffer(slen)
    ret = nacl.crypto_stream(stream, ctypes.c_ulonglong(slen), nonce, key)
    if ret:
        raise ValueError("Failed to init stream")
    return stream.raw


def crypto_stream_xor(msg, nonce, key):
    """
    Encrypts the given message using the given secret key and nonce

    The crypto_stream_xor function guarantees that the ciphertext is the
    plaintext (xor) the output of crypto_stream. Consequently
    crypto_stream_xor can also be used to decrypt
    """
    if len(key) != crypto_stream_KEYBYTES:
        raise ValueError("Invalid secret key")
    if len(nonce) != crypto_stream_NONCEBYTES:
        raise ValueError("Invalid nonce")

    stream = ctypes.create_string_buffer(len(msg))
    ret = nacl.crypto_stream_xor(
        stream, msg, ctypes.c_ulonglong(len(msg)), nonce, key)
    if ret:
        raise ValueError("Failed to init stream")
    return stream.raw
