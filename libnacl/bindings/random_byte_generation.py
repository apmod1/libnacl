# This notice is included to comply with the terms of the Apache License.
# This file includes portions of code from the original forked __init__.py file.
# The code was modified by Apurva Mody and subsequently placed in this file.

import ctypes
from libnacl import nacl
from libnacl.bindings.constants import HAS_RAND_SEED, randombytes_SEEDBYTES

#  Random byte generation


def randombytes(size):
    """
    Return a string of random bytes of the given size
    """
    buf = ctypes.create_string_buffer(size)
    nacl.randombytes(buf, ctypes.c_ulonglong(size))
    return buf.raw


def randombytes_buf(size):
    """
    Return a string of random bytes of the given size
    """
    size = int(size)
    buf = ctypes.create_string_buffer(size)
    nacl.randombytes_buf(buf, size)
    return buf.raw


def randombytes_buf_deterministic(size, seed):
    """
    Returns a string of random byles of the given size for a given seed.
    For a given seed, this function will always output the same sequence.
    Size can be up to 2^70 (256 GB).
    """

    if not HAS_RAND_SEED:
        raise ValueError(
            "Underlying Sodium library does not support randombytes_seedbytes"
        )
    if len(seed) != randombytes_SEEDBYTES:
        raise ValueError("Invalid key seed")

    size = int(size)
    buf = ctypes.create_string_buffer(size)
    nacl.randombytes_buf_deterministic(buf, size, seed)
    return buf.raw


def randombytes_close():
    """
    Close the file descriptor or the handle for the cryptographic service
    provider
    """
    nacl.randombytes_close()


def randombytes_random():
    """
    Return a random 32-bit unsigned value
    """
    return nacl.randombytes_random()


def randombytes_stir():
    """
    Generate a new key for the pseudorandom number generator

    The file descriptor for the entropy source is kept open, so that the
    generator can be reseeded even in a chroot() jail.
    """
    nacl.randombytes_stir()


def randombytes_uniform(upper_bound):
    """
    Return a value between 0 and upper_bound using a uniform distribution
    """
    return nacl.randombytes_uniform(upper_bound)
