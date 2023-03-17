import ctypes
from libnacl import nacl
from constants import *
from exceptions import CryptError

#  Pubkey defs


def crypto_box_keypair():
    """
    Generate and return a new keypair

    pk, sk = nacl.crypto_box_keypair()
    """
    pk = ctypes.create_string_buffer(crypto_box_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_box_SECRETKEYBYTES)
    nacl.crypto_box_keypair(pk, sk)
    return pk.raw, sk.raw


def crypto_box_seed_keypair(seed):
    """
    Generate and return a keypair from a key seed
    """
    if len(seed) != crypto_box_SEEDBYTES:
        raise ValueError("Invalid key seed")
    pk = ctypes.create_string_buffer(crypto_box_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_box_SECRETKEYBYTES)
    nacl.crypto_box_seed_keypair(pk, sk, seed)
    return pk.raw, sk.raw


def crypto_scalarmult_base(sk):
    """
    Compute and return the scalar product of a standard group element and the given integer.

    This can be used to derive a Curve25519 public key from a Curve25519 secret key,
    such as for usage with crypto_box and crypto_box_seal.
    """
    if len(sk) != crypto_box_SECRETKEYBYTES:
        raise ValueError("Invalid secret key")
    pk = ctypes.create_string_buffer(crypto_box_PUBLICKEYBYTES)
    if nacl.crypto_scalarmult_base(pk, sk):
        raise CryptError("Failed to compute scalar product")
    return pk.raw


def crypto_box(msg, nonce, pk, sk):
    """
    Using a public key and a secret key encrypt the given message. A nonce
    must also be passed in, never reuse the nonce

    enc_msg = nacl.crypto_box('secret message', <unique nonce>, <public key string>, <secret key string>)
    """
    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise ValueError("Invalid public key")
    if len(sk) != crypto_box_SECRETKEYBYTES:
        raise ValueError("Invalid secret key")
    if len(nonce) != crypto_box_NONCEBYTES:
        raise ValueError("Invalid nonce")
    pad = b"\x00" * crypto_box_ZEROBYTES + msg
    c = ctypes.create_string_buffer(len(pad))
    ret = nacl.crypto_box(c, pad, ctypes.c_ulonglong(len(pad)), nonce, pk, sk)
    if ret:
        raise CryptError("Unable to encrypt message")
    return c.raw[crypto_box_BOXZEROBYTES:]


def crypto_box_open(ctxt, nonce, pk, sk):
    """
    Decrypts a message given the receiver's private key, and sender's public key
    """
    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise ValueError("Invalid public key")
    if len(sk) != crypto_box_SECRETKEYBYTES:
        raise ValueError("Invalid secret key")
    if len(nonce) != crypto_box_NONCEBYTES:
        raise ValueError("Invalid nonce")
    pad = b"\x00" * crypto_box_BOXZEROBYTES + ctxt
    msg = ctypes.create_string_buffer(len(pad))
    ret = nacl.crypto_box_open(msg, pad, ctypes.c_ulonglong(len(pad)), nonce, pk, sk)
    if ret:
        raise CryptError("Unable to decrypt ciphertext")
    return msg.raw[crypto_box_ZEROBYTES:]


def crypto_box_easy(msg, nonce, pk, sk):
    """
    Using a public key and a secret key encrypt the given message. A nonce
    must also be passed in, never reuse the nonce

    enc_msg = nacl.crypto_box_easy('secret message', <unique nonce>, <public key string>, <secret key string>)
    """
    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise ValueError("Invalid public key")
    if len(sk) != crypto_box_SECRETKEYBYTES:
        raise ValueError("Invalid secret key")
    if len(nonce) != crypto_box_NONCEBYTES:
        raise ValueError("Invalid nonce")
    c = ctypes.create_string_buffer(len(msg) + crypto_box_MACBYTES)
    ret = nacl.crypto_box(c, msg, ctypes.c_ulonglong(len(msg)), nonce, pk, sk)
    if ret:
        raise CryptError("Unable to encrypt message")
    return c.raw


def crypto_box_open_easy(ctxt, nonce, pk, sk):
    """
    Decrypts a message given the receiver's private key, and sender's public key
    """
    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise ValueError("Invalid public key")
    if len(sk) != crypto_box_SECRETKEYBYTES:
        raise ValueError("Invalid secret key")
    if len(nonce) != crypto_box_NONCEBYTES:
        raise ValueError("Invalid nonce")
    msg = ctypes.create_string_buffer(len(ctxt) - crypto_box_MACBYTES)
    ret = nacl.crypto_box_open(msg, ctxt, ctypes.c_ulonglong(len(ctxt)), nonce, pk, sk)
    if ret:
        raise CryptError("Unable to decrypt ciphertext")
    return msg.raw[crypto_box_ZEROBYTES:]


def crypto_box_beforenm(pk, sk):
    """
    Partially performs the computation required for both encryption and decryption of data
    """
    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise ValueError("Invalid public key")
    if len(sk) != crypto_box_SECRETKEYBYTES:
        raise ValueError("Invalid secret key")
    k = ctypes.create_string_buffer(crypto_box_BEFORENMBYTES)
    ret = nacl.crypto_box_beforenm(k, pk, sk)
    if ret:
        raise CryptError("Unable to compute shared key")
    return k.raw


def crypto_box_afternm(msg, nonce, k):
    """
    Encrypts a given a message, using partial computed data
    """
    if len(k) != crypto_box_BEFORENMBYTES:
        raise ValueError("Invalid shared key")
    if len(nonce) != crypto_box_NONCEBYTES:
        raise ValueError("Invalid nonce")
    pad = b"\x00" * crypto_box_ZEROBYTES + msg
    ctxt = ctypes.create_string_buffer(len(pad))
    ret = nacl.crypto_box_afternm(ctxt, pad, ctypes.c_ulonglong(len(pad)), nonce, k)
    if ret:
        raise CryptError("Unable to encrypt messsage")
    return ctxt.raw[crypto_box_BOXZEROBYTES:]


def crypto_box_open_afternm(ctxt, nonce, k):
    """
    Decrypts a ciphertext ctxt given k
    """
    if len(k) != crypto_box_BEFORENMBYTES:
        raise ValueError("Invalid shared key")
    if len(nonce) != crypto_box_NONCEBYTES:
        raise ValueError("Invalid nonce")
    pad = b"\x00" * crypto_box_BOXZEROBYTES + ctxt
    msg = ctypes.create_string_buffer(len(pad))
    ret = nacl.crypto_box_open_afternm(msg, pad, ctypes.c_ulonglong(len(pad)), nonce, k)
    if ret:
        raise CryptError("unable to decrypt message")
    return msg.raw[crypto_box_ZEROBYTES:]


def crypto_box_easy_afternm(msg, nonce, k):
    """
    Using a precalculated shared key, encrypt the given message. A nonce
    must also be passed in, never reuse the nonce

    enc_msg = nacl.crypto_box_easy_afternm('secret message', <unique nonce>, <shared key string>)
    """
    if len(k) != crypto_box_BEFORENMBYTES:
        raise ValueError("Invalid shared key")
    if len(nonce) != crypto_box_NONCEBYTES:
        raise ValueError("Invalid nonce")
    ctxt = ctypes.create_string_buffer(len(msg) + crypto_box_MACBYTES)
    ret = nacl.crypto_box_easy_afternm(
        ctxt, msg, ctypes.c_ulonglong(len(msg)), nonce, k
    )
    if ret:
        raise CryptError("Unable to encrypt messsage")
    return ctxt.raw


def crypto_box_open_easy_afternm(ctxt, nonce, k):
    """
    Decrypts a ciphertext ctxt given k
    """
    if len(k) != crypto_box_BEFORENMBYTES:
        raise ValueError("Invalid shared key")
    if len(nonce) != crypto_box_NONCEBYTES:
        raise ValueError("Invalid nonce")
    msg = ctypes.create_string_buffer(len(ctxt) - crypto_box_MACBYTES)
    ret = nacl.crypto_box_open_easy_afternm(
        msg, ctxt, ctypes.c_ulonglong(len(ctxt)), nonce, k
    )
    if ret:
        raise CryptError("unable to decrypt message")
    return msg.raw


def crypto_box_seal(msg, pk):
    """
    Using a public key to encrypt the given message. The identity of the sender cannot be verified.

    enc_msg = nacl.crypto_box_seal('secret message', <public key string>)
    """
    if not HAS_SEAL:
        raise ValueError("Underlying Sodium library does not support sealed boxes")
    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise ValueError("Invalid public key")
    if not isinstance(msg, bytes):
        raise TypeError("Message must be bytes")

    c = ctypes.create_string_buffer(len(msg) + crypto_box_SEALBYTES)
    ret = nacl.crypto_box_seal(c, msg, ctypes.c_ulonglong(len(msg)), pk)
    if ret:
        raise CryptError("Unable to encrypt message")
    return c.raw


def crypto_box_seal_open(ctxt, pk, sk):
    """
    Decrypts a message given the receiver's public and private key.
    """
    if not HAS_SEAL:
        raise ValueError("Underlying Sodium library does not support sealed boxes")
    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise ValueError("Invalid public key")
    if len(sk) != crypto_box_SECRETKEYBYTES:
        raise ValueError("Invalid secret key")
    if not isinstance(ctxt, bytes):
        raise TypeError("Message must be bytes")

    c = ctypes.create_string_buffer(len(ctxt) - crypto_box_SEALBYTES)
    ret = nacl.crypto_box_seal_open(c, ctxt, ctypes.c_ulonglong(len(ctxt)), pk, sk)
    if ret:
        raise CryptError("Unable to decrypt message")
    return c.raw
