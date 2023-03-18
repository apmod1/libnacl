# This notice is included to comply with the terms of the Apache License.
# This file includes portions of code from the original forked __init__.py file.
# The code was modified by Apurva Mody and subsequently placed in this file.

import ctypes
from libnacl import nacl, DOC_RUN

if not DOC_RUN:
    sodium_init = nacl.sodium_init
    sodium_init.res_type = ctypes.c_int
    if sodium_init() < 0:
        raise RuntimeError("sodium_init() call failed!")
    #  Define constants
    try:
        crypto_box_SEALBYTES = nacl.crypto_box_sealbytes()
        HAS_SEAL = True
    except AttributeError:
        HAS_SEAL = False
    try:
        crypto_aead_aes256gcm_KEYBYTES = nacl.crypto_aead_aes256gcm_keybytes()
        crypto_aead_aes256gcm_NPUBBYTES = nacl.crypto_aead_aes256gcm_npubbytes()
        crypto_aead_aes256gcm_ABYTES = nacl.crypto_aead_aes256gcm_abytes()
        HAS_AEAD_AES256GCM = bool(nacl.crypto_aead_aes256gcm_is_available())
        crypto_aead_chacha20poly1305_ietf_KEYBYTES = (
            nacl.crypto_aead_chacha20poly1305_ietf_keybytes()
        )
        crypto_aead_chacha20poly1305_ietf_NPUBBYTES = (
            nacl.crypto_aead_chacha20poly1305_ietf_npubbytes()
        )
        crypto_aead_chacha20poly1305_ietf_ABYTES = (
            nacl.crypto_aead_chacha20poly1305_ietf_abytes()
        )
        HAS_AEAD_CHACHA20POLY1305_IETF = True
        HAS_AEAD = True
    except AttributeError:
        HAS_AEAD_AES256GCM = False
        HAS_AEAD_CHACHA20POLY1305_IETF = False
        HAS_AEAD = False

    crypto_box_SECRETKEYBYTES = nacl.crypto_box_secretkeybytes()
    crypto_box_SEEDBYTES = nacl.crypto_box_seedbytes()
    crypto_box_PUBLICKEYBYTES = nacl.crypto_box_publickeybytes()
    crypto_box_NONCEBYTES = nacl.crypto_box_noncebytes()
    crypto_box_ZEROBYTES = nacl.crypto_box_zerobytes()
    crypto_box_BOXZEROBYTES = nacl.crypto_box_boxzerobytes()
    crypto_box_BEFORENMBYTES = nacl.crypto_box_beforenmbytes()
    crypto_scalarmult_BYTES = nacl.crypto_scalarmult_bytes()
    crypto_scalarmult_SCALARBYTES = nacl.crypto_scalarmult_scalarbytes()
    crypto_sign_BYTES = nacl.crypto_sign_bytes()
    crypto_sign_SEEDBYTES = nacl.crypto_sign_secretkeybytes() // 2
    crypto_sign_PUBLICKEYBYTES = nacl.crypto_sign_publickeybytes()
    crypto_sign_SECRETKEYBYTES = nacl.crypto_sign_secretkeybytes()
    crypto_sign_ed25519_PUBLICKEYBYTES = nacl.crypto_sign_ed25519_publickeybytes()
    crypto_sign_ed25519_SECRETKEYBYTES = nacl.crypto_sign_ed25519_secretkeybytes()
    crypto_box_MACBYTES = crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES
    crypto_secretbox_KEYBYTES = nacl.crypto_secretbox_keybytes()
    crypto_secretbox_NONCEBYTES = nacl.crypto_secretbox_noncebytes()
    crypto_secretbox_ZEROBYTES = nacl.crypto_secretbox_zerobytes()
    crypto_secretbox_BOXZEROBYTES = nacl.crypto_secretbox_boxzerobytes()
    crypto_secretbox_MACBYTES = (
        crypto_secretbox_ZEROBYTES - crypto_secretbox_BOXZEROBYTES
    )
    crypto_stream_KEYBYTES = nacl.crypto_stream_keybytes()
    crypto_stream_NONCEBYTES = nacl.crypto_stream_noncebytes()
    crypto_auth_BYTES = nacl.crypto_auth_bytes()
    crypto_auth_KEYBYTES = nacl.crypto_auth_keybytes()
    crypto_onetimeauth_BYTES = nacl.crypto_onetimeauth_bytes()
    crypto_onetimeauth_KEYBYTES = nacl.crypto_onetimeauth_keybytes()
    crypto_generichash_BYTES = nacl.crypto_generichash_bytes()
    crypto_generichash_BYTES_MIN = nacl.crypto_generichash_bytes_min()
    crypto_generichash_BYTES_MAX = nacl.crypto_generichash_bytes_max()
    crypto_generichash_KEYBYTES = nacl.crypto_generichash_keybytes()
    crypto_generichash_KEYBYTES_MIN = nacl.crypto_generichash_keybytes_min()
    crypto_generichash_KEYBYTES_MAX = nacl.crypto_generichash_keybytes_max()
    crypto_scalarmult_curve25519_BYTES = nacl.crypto_scalarmult_curve25519_bytes()
    crypto_hash_BYTES = nacl.crypto_hash_sha512_bytes()
    crypto_hash_sha256_BYTES = nacl.crypto_hash_sha256_bytes()
    crypto_hash_sha512_BYTES = nacl.crypto_hash_sha512_bytes()
    crypto_verify_16_BYTES = nacl.crypto_verify_16_bytes()
    crypto_verify_32_BYTES = nacl.crypto_verify_32_bytes()
    crypto_verify_64_BYTES = nacl.crypto_verify_64_bytes()

    try:
        randombytes_SEEDBYTES = nacl.randombytes_seedbytes()
        HAS_RAND_SEED = True
    except AttributeError:
        HAS_RAND_SEED = False

    try:
        crypto_kdf_PRIMITIVE = nacl.crypto_kdf_primitive()
        crypto_kdf_BYTES_MIN = nacl.crypto_kdf_bytes_min()
        crypto_kdf_BYTES_MAX = nacl.crypto_kdf_bytes_max()
        crypto_kdf_CONTEXTBYTES = nacl.crypto_kdf_contextbytes()
        crypto_kdf_KEYBYTES = nacl.crypto_kdf_keybytes()
        HAS_CRYPT_KDF = True
    except AttributeError:
        HAS_CRYPT_KDF = False

    try:
        crypto_kx_PUBLICKEYBYTES = nacl.crypto_kx_publickeybytes()
        crypto_kx_SECRETKEYBYTES = nacl.crypto_kx_secretkeybytes()
        crypto_kx_SEEDBYTES = nacl.crypto_kx_seedbytes()
        crypto_kx_SESSIONKEYBYTES = nacl.crypto_kx_sessionkeybytes()
        crypto_kx_PRIMITIVE = nacl.crypto_kx_primitive()
        HAS_CRYPT_KX = True
    except AttributeError:
        HAS_CRYPT_KX = False
