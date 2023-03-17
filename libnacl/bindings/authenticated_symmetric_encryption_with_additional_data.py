import ctypes
from libnacl import nacl
from libnacl.bindings.constants import (
    HAS_AEAD_AES256GCM,
    crypto_aead_aes256gcm_KEYBYTES,
    crypto_aead_aes256gcm_NPUBBYTES,
    crypto_aead_aes256gcm_ABYTES,
    HAS_AEAD_CHACHA20POLY1305_IETF,
    crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    crypto_aead_chacha20poly1305_ietf_ABYTES,
    crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
)

#  Authenticated Symmetric Encryption with Additional Data


def crypto_aead_aes256gcm_encrypt(message, aad, nonce, key):
    """Encrypts and authenticates a message with public additional data using the given secret key, and nonce

    Args:
        message (bytes): a message to encrypt
        aad  (bytes): additional public data to authenticate
        nonce (bytes): nonce, does not have to be confidential must be
            `crypto_aead_aes256gcm_NPUBBYTES` in length
        key (bytes): secret key, must be `crypto_aead_aes256gcm_KEYBYTES` in
            length

    Returns:
        bytes: the ciphertext

    Raises:
        ValueError: if arguments' length is wrong or the operation has failed.
    """
    if not HAS_AEAD_AES256GCM:
        raise ValueError("Underlying Sodium library does not support AES256-GCM AEAD")

    if len(key) != crypto_aead_aes256gcm_KEYBYTES:
        raise ValueError("Invalid key")

    if len(nonce) != crypto_aead_aes256gcm_NPUBBYTES:
        raise ValueError("Invalid nonce")

    length = len(message) + crypto_aead_aes256gcm_ABYTES
    clen = ctypes.c_ulonglong()
    c = ctypes.create_string_buffer(length)
    ret = nacl.crypto_aead_aes256gcm_encrypt(
        c,
        ctypes.pointer(clen),
        message,
        ctypes.c_ulonglong(len(message)),
        aad,
        ctypes.c_ulonglong(len(aad)),
        None,
        nonce,
        key,
    )
    if ret:
        raise ValueError("Failed to encrypt message")
    return c.raw


def crypto_aead_chacha20poly1305_ietf_encrypt(message, aad, nonce, key):
    """Encrypts and authenticates a message with public additional data using the given secret key, and nonce

    Args:
        message (bytes): a message to encrypt
        aad  (bytes): additional public data to authenticate
        nonce (bytes): nonce, does not have to be confidential must be
            `crypto_aead_chacha20poly1305_ietf_NPUBBYTES` in length
        key (bytes): secret key, must be `crypto_aead_chacha20poly1305_ietf_KEYBYTES` in
            length

    Returns:
        bytes: the ciphertext

    Raises:
        ValueError: if arguments' length is wrong or the operation has failed.
    """
    if not HAS_AEAD_CHACHA20POLY1305_IETF:
        raise ValueError(
            "Underlying Sodium library does not support IETF variant of ChaCha20Poly1305 AEAD"
        )

    if len(key) != crypto_aead_chacha20poly1305_ietf_KEYBYTES:
        raise ValueError("Invalid key")

    if len(nonce) != crypto_aead_chacha20poly1305_ietf_NPUBBYTES:
        raise ValueError("Invalid nonce")

    length = len(message) + crypto_aead_chacha20poly1305_ietf_ABYTES
    clen = ctypes.c_ulonglong()
    c = ctypes.create_string_buffer(length)
    ret = nacl.crypto_aead_chacha20poly1305_ietf_encrypt(
        c,
        ctypes.pointer(clen),
        message,
        ctypes.c_ulonglong(len(message)),
        aad,
        ctypes.c_ulonglong(len(aad)),
        None,
        nonce,
        key,
    )
    if ret:
        raise ValueError("Failed to encrypt message")
    return c.raw


def crypto_aead_aes256gcm_decrypt(ctxt, aad, nonce, key):
    """
    Decrypts a ciphertext ctxt given the key, nonce, and aad. If the aad
    or ciphertext were altered then the decryption will fail.
    """
    if not HAS_AEAD_AES256GCM:
        raise ValueError("Underlying Sodium library does not support AES256-GCM AEAD")

    if len(key) != crypto_aead_aes256gcm_KEYBYTES:
        raise ValueError("Invalid key")

    if len(nonce) != crypto_aead_aes256gcm_NPUBBYTES:
        raise ValueError("Invalid nonce")

    length = len(ctxt) - crypto_aead_aes256gcm_ABYTES
    mlen = ctypes.c_ulonglong()
    m = ctypes.create_string_buffer(length)

    ret = nacl.crypto_aead_aes256gcm_decrypt(
        m,
        ctypes.byref(mlen),
        None,
        ctxt,
        ctypes.c_ulonglong(len(ctxt)),
        aad,
        ctypes.c_ulonglong(len(aad)),
        nonce,
        key,
    )
    if ret:
        raise ValueError("Failed to decrypt message")
    return m.raw


def crypto_aead_chacha20poly1305_ietf_decrypt(ctxt, aad, nonce, key):
    """
    Decrypts a ciphertext ctxt given the key, nonce, and aad. If the aad
    or ciphertext were altered then the decryption will fail.
    """
    if not HAS_AEAD_CHACHA20POLY1305_IETF:
        raise ValueError(
            "Underlying Sodium library does not support IETF variant of ChaCha20Poly1305 AEAD"
        )

    if len(key) != crypto_aead_chacha20poly1305_ietf_KEYBYTES:
        raise ValueError("Invalid key")

    if len(nonce) != crypto_aead_chacha20poly1305_ietf_NPUBBYTES:
        raise ValueError("Invalid nonce")

    length = len(ctxt) - crypto_aead_chacha20poly1305_ietf_ABYTES
    mlen = ctypes.c_ulonglong()
    m = ctypes.create_string_buffer(length)

    ret = nacl.crypto_aead_chacha20poly1305_ietf_decrypt(
        m,
        ctypes.byref(mlen),
        None,
        ctxt,
        ctypes.c_ulonglong(len(ctxt)),
        aad,
        ctypes.c_ulonglong(len(aad)),
        nonce,
        key,
    )
    if ret:
        raise ValueError("Failed to decrypt message")
    return m.raw
