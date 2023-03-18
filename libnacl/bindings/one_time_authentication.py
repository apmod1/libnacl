# This notice is included to comply with the terms of the Apache License.
# This file includes portions of code from the original forked __init__.py file.
# The code was modified by Apurva Mody and subsequently placed in this file.

import ctypes
from libnacl import nacl
from libnacl.bindings.constants import (
    crypto_onetimeauth_KEYBYTES,
    crypto_onetimeauth_BYTES,
)

#  One time authentication


def crypto_onetimeauth_primitive():
    """
    Return the onetimeauth underlying primitive

    Returns:
        str: always ``poly1305``
    """
    func = nacl.crypto_onetimeauth_primitive
    func.restype = ctypes.c_char_p
    return func().decode()


def crypto_onetimeauth(message, key):
    """
    Constructs a one time authentication token for the given message using
    a given secret key

    Args:
        message (bytes): message to authenticate.
        key (bytes): secret key - must be of crypto_onetimeauth_KEYBYTES length.

    Returns:
        bytes: an authenticator, of crypto_onetimeauth_BYTES length.

    Raises:
        ValueError: if arguments' length is wrong.
    """
    if len(key) != crypto_onetimeauth_KEYBYTES:
        raise ValueError("Invalid secret key")

    tok = ctypes.create_string_buffer(crypto_onetimeauth_BYTES)
    #  cannot fail
    _ = nacl.crypto_onetimeauth(
        tok, message, ctypes.c_ulonglong(len(message)), key)

    return tok.raw[:crypto_onetimeauth_BYTES]


def crypto_onetimeauth_verify(token, message, key):
    """
    Verifies, in constant time, that ``token`` is a correct authenticator for
    the message using the secret key.

    Args:
        token (bytes): an authenticator of crypto_onetimeauth_BYTES length.
        message (bytes): The message to authenticate.
        key: key (bytes): secret key - must be of crypto_onetimeauth_KEYBYTES
            length.

    Returns:
        bytes: secret key - must be of crypto_onetimeauth_KEYBYTES length.

    Raises:
        ValueError: if arguments' length is wrong or verification has failed.
    """
    if len(key) != crypto_onetimeauth_KEYBYTES:
        raise ValueError("Invalid secret key")
    if len(token) != crypto_onetimeauth_BYTES:
        raise ValueError("Invalid authenticator")

    ret = nacl.crypto_onetimeauth_verify(
        token, message, ctypes.c_ulonglong(len(message)), key
    )
    if ret:
        raise ValueError("Failed to auth message")
    return message
