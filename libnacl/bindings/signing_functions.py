# This notice is included to comply with the terms of the Apache License.
# This file includes portions of code from the original forked __init__.py file.
# The code was modified by Apurva Mody and subsequently placed in this file.

import ctypes
from libnacl import nacl
from libnacl.bindings.constants import (
    crypto_sign_PUBLICKEYBYTES,
    crypto_sign_BYTES,
    crypto_sign_SECRETKEYBYTES,
    crypto_sign_ed25519_PUBLICKEYBYTES,
    crypto_sign_ed25519_SECRETKEYBYTES,
    crypto_sign_SEEDBYTES,
)
from libnacl.bindings.exceptions import CryptError

#  Signing functions


def crypto_sign_keypair():
    """
    Generates a signing/verification key pair
    """
    vk = ctypes.create_string_buffer(crypto_sign_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_sign_SECRETKEYBYTES)
    ret = nacl.crypto_sign_keypair(vk, sk)
    if ret:
        raise ValueError("Failed to generate keypair")
    return vk.raw, sk.raw


def crypto_sign_ed25519_keypair():
    """
    Generates a signing/verification Ed25519 key pair
    """
    vk = ctypes.create_string_buffer(crypto_sign_ed25519_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_sign_ed25519_SECRETKEYBYTES)
    ret = nacl.crypto_sign_ed25519_keypair(vk, sk)
    if ret:
        raise ValueError("Failed to generate keypair")
    return vk.raw, sk.raw


def crypto_sign_ed25519_sk_to_pk(sk):
    """
    Extract the public key from the secret key
    """
    if len(sk) != crypto_sign_ed25519_SECRETKEYBYTES:
        raise ValueError("Invalid secret key")

    pk = ctypes.create_string_buffer(crypto_sign_PUBLICKEYBYTES)
    ret = nacl.crypto_sign_ed25519_sk_to_pk(pk, sk)
    if ret:
        raise ValueError("Failed to generate public key")
    return pk.raw


def crypto_sign_ed25519_sk_to_seed(sk):
    """
    Extract the seed from the secret key
    """
    if len(sk) != crypto_sign_ed25519_SECRETKEYBYTES:
        raise ValueError("Invalid secret key")

    seed = ctypes.create_string_buffer(crypto_sign_SEEDBYTES)
    ret = nacl.crypto_sign_ed25519_sk_to_seed(seed, sk)
    if ret:
        raise ValueError("Failed to generate seed")
    return seed.raw


def crypto_sign(msg, sk):
    """
    Sign the given message with the given signing key
    """
    if len(sk) != crypto_sign_SECRETKEYBYTES:
        raise ValueError("Invalid secret key")

    sig = ctypes.create_string_buffer(len(msg) + crypto_sign_BYTES)
    slen = ctypes.pointer(ctypes.c_ulonglong())
    ret = nacl.crypto_sign(sig, slen, msg, ctypes.c_ulonglong(len(msg)), sk)
    if ret:
        raise ValueError("Failed to sign message")
    return sig.raw


def crypto_sign_detached(msg, sk):
    """
    Return signature for the given message with the given signing key
    """
    if len(sk) != crypto_sign_SECRETKEYBYTES:
        raise ValueError("Invalid secret key")

    sig = ctypes.create_string_buffer(crypto_sign_BYTES)
    slen = ctypes.pointer(ctypes.c_ulonglong())
    ret = nacl.crypto_sign_detached(
        sig, slen, msg, ctypes.c_ulonglong(len(msg)), sk)
    if ret:
        raise ValueError("Failed to sign message")
    return sig.raw[: slen.contents.value]


def crypto_sign_seed_keypair(seed):
    """
    Computes and returns the secret and verify keys from the given seed
    """
    if len(seed) != crypto_sign_SEEDBYTES:
        raise ValueError("Invalid Seed")

    sk = ctypes.create_string_buffer(crypto_sign_SECRETKEYBYTES)
    vk = ctypes.create_string_buffer(crypto_sign_PUBLICKEYBYTES)

    ret = nacl.crypto_sign_seed_keypair(vk, sk, seed)
    if ret:
        raise CryptError("Failed to generate keypair from seed")
    return (vk.raw, sk.raw)


def crypto_sign_open(sig, vk):
    """
    Verifies the signed message sig using the signer's verification key
    """
    if len(vk) != crypto_sign_PUBLICKEYBYTES:
        raise ValueError("Invalid public key")

    msg = ctypes.create_string_buffer(len(sig))
    msglen = ctypes.c_ulonglong()
    msglenp = ctypes.pointer(msglen)
    ret = nacl.crypto_sign_open(
        msg, msglenp, sig, ctypes.c_ulonglong(len(sig)), vk)
    if ret:
        raise ValueError("Failed to validate message")
    return msg.raw[: msglen.value]


#  pylint: disable=invalid-slice-index


def crypto_sign_verify_detached(sig, msg, vk):
    """
    Verifies that sig is a valid signature for the message msg using the signer's verification key
    """
    if len(sig) != crypto_sign_BYTES:
        raise ValueError("Invalid signature")
    if len(vk) != crypto_sign_PUBLICKEYBYTES:
        raise ValueError("Invalid public key")

    ret = nacl.crypto_sign_verify_detached(
        sig, msg, ctypes.c_ulonglong(len(msg)), vk)
    if ret:
        raise ValueError("Failed to validate message")
    return msg
