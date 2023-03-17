import ctypes
from libnacl import nacl
from constants import *
#  Generic Hash


def crypto_generichash(msg, key=None):
    '''
    Compute the blake2 hash of the given message with a given key
    '''
    hbuf = ctypes.create_string_buffer(crypto_generichash_BYTES)
    if key:
        key_len = len(key)
    else:
        key_len = 0
    nacl.crypto_generichash(
            hbuf,
            ctypes.c_size_t(len(hbuf)),
            msg,
            ctypes.c_ulonglong(len(msg)),
            key,
            ctypes.c_size_t(key_len))
    return hbuf.raw


