import ctypes
from libnacl import nacl
from libnacl.bindings.constants import crypto_auth_KEYBYTES, crypto_auth_BYTES

#  Authentication


def crypto_auth(msg, key):
    """
    Constructs a one time authentication token for the given message msg
    using a given secret key
    """
    if len(key) != crypto_auth_KEYBYTES:
        raise ValueError("Invalid secret key")

    tok = ctypes.create_string_buffer(crypto_auth_BYTES)
    ret = nacl.crypto_auth(tok, msg, ctypes.c_ulonglong(len(msg)), key)
    if ret:
        raise ValueError("Failed to auth msg")
    return tok.raw[:crypto_auth_BYTES]


def crypto_auth_verify(tok, msg, key):
    """
    Verifies that the given authentication token is correct for the given
    message and key
    """
    if len(key) != crypto_auth_KEYBYTES:
        raise ValueError("Invalid secret key")
    if len(tok) != crypto_auth_BYTES:
        raise ValueError("Invalid authenticator")

    ret = nacl.crypto_auth_verify(tok, msg, ctypes.c_ulonglong(len(msg)), key)
    if ret:
        raise ValueError("Failed to auth msg")
    return msg
