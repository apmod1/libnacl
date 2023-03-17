import ctypes
from libnacl import nacl
from constants import *
from exceptions import CryptError

#  Utility functions


def sodium_library_version_major():
    """
    Return the major version number
    """
    return nacl.sodium_library_version_major()


def sodium_library_version_minor():
    """
    Return the minor version number
    """
    return nacl.sodium_library_version_minor()


def sodium_version_string():
    """
    Return the version string
    """
    func = nacl.sodium_version_string
    func.restype = ctypes.c_char_p
    return func()


def crypto_sign_ed25519_pk_to_curve25519(ed25519_pk):
    """
    Convert an Ed25519 public key to a Curve25519 public key
    """
    if len(ed25519_pk) != crypto_sign_ed25519_PUBLICKEYBYTES:
        raise ValueError("Invalid public key")

    curve25519_pk = ctypes.create_string_buffer(crypto_scalarmult_curve25519_BYTES)
    ret = nacl.crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, ed25519_pk)
    if ret:
        raise CryptError("Failed to generate Curve25519 public key")
    return curve25519_pk.raw


def crypto_sign_ed25519_sk_to_curve25519(ed25519_sk):
    """
    Convert an Ed25519 secret key to a Curve25519 secret key
    """
    if len(ed25519_sk) != crypto_sign_ed25519_SECRETKEYBYTES:
        raise ValueError("Invalid secret key")

    curve25519_sk = ctypes.create_string_buffer(crypto_scalarmult_curve25519_BYTES)
    ret = nacl.crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, ed25519_sk)
    if ret:
        raise CryptError("Failed to generate Curve25519 secret key")
    return curve25519_sk.raw
