"""
Basic tests for verify functions
"""

import libnacl.bindings.random_byte_generation as rbg
import libnacl.bindings.string_cmp as sc
from libnacl.bindings.constants import crypto_verify_16_BYTES, crypto_verify_32_BYTES, crypto_verify_64_BYTES
import unittest


# These are copied from libsodium test suite
class TestVerify(unittest.TestCase):
    def test_verify16(self):
        v16 = rbg.randombytes_buf(16)
        v16x = v16[:]
        self.assertTrue(sc.crypto_verify_16(v16, v16x))
        self.assertTrue(sc.bytes_eq(v16, v16x))
        v16x = bytearray(v16x)
        i = rbg.randombytes_random() & 15
        v16x[i] = (v16x[i] + 1) % 256
        v16x = bytes(v16x)
        self.assertFalse(sc.crypto_verify_16(v16, v16x))
        self.assertFalse(sc.bytes_eq(v16, v16x))

        self.assertEqual(crypto_verify_16_BYTES, 16)

    def test_verify32(self):
        v32 = rbg.randombytes_buf(32)
        v32x = v32[:]
        self.assertTrue(sc.crypto_verify_32(v32, v32x))
        self.assertTrue(sc.bytes_eq(v32, v32x))
        v32x = bytearray(v32x)
        i = rbg.randombytes_random() & 31
        v32x[i] = (v32x[i] + 1) % 256
        v32x = bytes(v32x)
        self.assertFalse(sc.crypto_verify_32(v32, v32x))
        self.assertFalse(sc.bytes_eq(v32, v32x))

        self.assertEqual(crypto_verify_32_BYTES, 32)

    def test_verify64(self):
        v64 = rbg.randombytes_buf(64)
        v64x = v64[:]
        self.assertTrue(sc.crypto_verify_64(v64, v64x))
        self.assertTrue(sc.bytes_eq(v64, v64x))
        v64x = bytearray(v64x)
        i = rbg.randombytes_random() & 63
        v64x[i] = (v64x[i] + 1) % 256
        v64x = bytes(v64x)
        self.assertFalse(sc.crypto_verify_64(v64, v64x))
        self.assertFalse(sc.bytes_eq(v64, v64x))

        self.assertEqual(crypto_verify_64_BYTES, 64)


class TestVerifyBytesEq(unittest.TestCase):
    def test_equal(self):
        a = rbg.randombytes_buf(122)
        b = a[:]
        self.assertTrue(sc.bytes_eq(a, b))

    def test_different(self):
        a = rbg.randombytes_buf(122)
        b = bytearray(a)
        b[87] = (b[87] + 1) % 256
        b = bytes(b)
        self.assertFalse(sc.bytes_eq(a, b))

    def test_invalid_type(self):
        a = rbg.randombytes_buf(122)
        b = bytearray(a)
        with self.assertRaises(TypeError):
            sc.bytes_eq(a, b)

    def test_different_length(self):
        a = rbg.randombytes_buf(122)
        b = a[:-1]
        self.assertFalse(sc.bytes_eq(a, b))
