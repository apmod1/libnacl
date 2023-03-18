# This notice is included to comply with the terms of the Apache License.
# This file includes portions of code from the original forked __init__.py file.
# The code was modified by Apurva Mody and subsequently placed in this file.

import ctypes
from libnacl import nacl
from libnacl.bindings.constants import (
    crypto_secretbox_KEYBYTES,
    crypto_secretbox_NONCEBYTES,
    crypto_secretbox_ZEROBYTES,
    crypto_secretbox_BOXZEROBYTES,
)

#  Authenticated Symmetric Encryption


def crypto_secretbox(message, nonce, key):
    """Encrypts and authenticates a message using the given secret key, and nonce

    Args:
        message (bytes): a message to encrypt
        nonce (bytes): nonce, does not have to be confidential must be
            `crypto_secretbox_NONCEBYTES` in length
        key (bytes): secret key, must be `crypto_secretbox_KEYBYTES` in
            length

    Returns:
        bytes: the ciphertext

    Raises:
        ValueError: if arguments' length is wrong or the operation has failed.
    """
    if len(key) != crypto_secretbox_KEYBYTES:
        raise ValueError("Invalid key")

    if len(nonce) != crypto_secretbox_NONCEBYTES:
        raise ValueError("Invalid nonce")

    pad = b"\x00" * crypto_secretbox_ZEROBYTES + message
    ctxt = ctypes.create_string_buffer(len(pad))
    ret = nacl.crypto_secretbox(
        ctxt, pad, ctypes.c_ulonglong(len(pad)), nonce, key)
    if ret:
        raise ValueError("Failed to encrypt message")
    return ctxt.raw[crypto_secretbox_BOXZEROBYTES:]


def crypto_secretbox_open(ctxt, nonce, key):
    """
    Decrypts a ciphertext ctxt given the receivers private key, and senders
    public key
    """
    if len(key) != crypto_secretbox_KEYBYTES:
        raise ValueError("Invalid key")

    if len(nonce) != crypto_secretbox_NONCEBYTES:
        raise ValueError("Invalid nonce")

    pad = b"\x00" * crypto_secretbox_BOXZEROBYTES + ctxt
    msg = ctypes.create_string_buffer(len(pad))
    ret = nacl.crypto_secretbox_open(
        msg, pad, ctypes.c_ulonglong(len(pad)), nonce, key)
    if ret:
        raise ValueError("Failed to decrypt message")
    return msg.raw[crypto_secretbox_ZEROBYTES:]
