import ctypes
from libnacl import nacl
from libnacl.bindings.constants import (
    HAS_CRYPT_KX,
    crypto_kx_PUBLICKEYBYTES,
    crypto_kx_SECRETKEYBYTES,
    crypto_kx_SEEDBYTES,
    crypto_kx_SESSIONKEYBYTES,
)

#  Key Exchange API


def crypto_kx_keypair():
    """
    Generate and return a new keypair
    """
    if not HAS_CRYPT_KX:
        raise ValueError("Underlying Sodium library does not support crypto_kx")
    pk = ctypes.create_string_buffer(crypto_kx_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_kx_SECRETKEYBYTES)
    nacl.crypto_kx_keypair(pk, sk)
    return pk.raw, sk.raw


def crypto_kx_seed_keypair(seed):
    """
    Generate and return a keypair from a key seed
    """
    if not HAS_CRYPT_KX:
        raise ValueError("Underlying Sodium library does not support crypto_kx")

    if len(seed) != crypto_kx_SEEDBYTES:
        raise ValueError("Invalid key seed")
    pk = ctypes.create_string_buffer(crypto_kx_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_kx_SECRETKEYBYTES)
    nacl.crypto_kx_seed_keypair(pk, sk, seed)
    return pk.raw, sk.raw


def crypto_kx_client_session_keys(client_pk, client_sk, server_pk):
    """
    Computes a pair of shared keys (rx and tx) using the client's public key client_pk,
    the client's secret key client_sk and the server's public key server_pk.
    Status returns 0 on success, or -1 if the server's public key is not acceptable.
    """
    if not HAS_CRYPT_KX:
        raise ValueError("Underlying Sodium library does not support crypto_kx")

    rx = ctypes.create_string_buffer(crypto_kx_SESSIONKEYBYTES)
    tx = ctypes.create_string_buffer(crypto_kx_SESSIONKEYBYTES)
    status = nacl.crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk)
    return rx.raw, tx.raw, status


def crypto_kx_server_session_keys(server_pk, server_sk, client_pk):
    """
    Computes a pair of shared keys (rx and tx) using the server's public key server_pk,
    the server's secret key server_sk and the client's public key client_pk.
    Status returns 0 on success, or -1 if the client's public key is not acceptable.
    """
    if not HAS_CRYPT_KX:
        raise ValueError("Underlying Sodium library does not support crypto_kx")

    rx = ctypes.create_string_buffer(crypto_kx_SESSIONKEYBYTES)
    tx = ctypes.create_string_buffer(crypto_kx_SESSIONKEYBYTES)
    status = nacl.crypto_kx_server_session_keys(rx, tx, server_pk, server_sk, client_pk)
    return rx.raw, tx.raw, status
