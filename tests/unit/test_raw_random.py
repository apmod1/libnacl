"""
Basic tests for randombytes_* functions
"""

import libnacl.bindings.random_byte_generation as rbg
import libnacl.bindings.key_derivation_api as kda
import libnacl.bindings.key_exchange_api as kea
import unittest


class TestRandomBytes(unittest.TestCase):
    def test_randombytes_random(self):
        self.assertIsInstance(rbg.randombytes_random(), int)

    def test_randombytes_uniform(self):
        self.assertIsInstance(rbg.randombytes_uniform(200), int)

        freq = {rbg.randombytes_uniform(256): 1 for _ in range(65536)}

        self.assertEqual(256, len(freq))
        self.assertTrue(all(freq.values()))

    def test_randombytes(self):
        'copied from libsodium default/randombytes.c'

        data = rbg.randombytes(65536)

        freq = {x: 1 for x in data}

        self.assertEqual(256, len(freq))
        self.assertTrue(all(freq.values()))

    def test_randombytes_buf_deterministic(self):

        seed = rbg.randombytes_buf(32)
        seed2 = rbg.randombytes_buf(32)
        data = rbg.randombytes_buf_deterministic(32, seed)
        data2 = rbg.randombytes_buf_deterministic(32, seed)
        data3 = rbg.randombytes_buf_deterministic(32, seed2)

        self.assertEqual(32, len(data))
        self.assertEqual(32, len(data))
        self.assertEqual(32, len(data))
        self.assertEqual(data, data2)
        self.assertNotEqual(data, data3)

    def test_crypto_kdf_keygen(self):

        master_key = kda.crypto_kdf_keygen()

        freq = {x: 1 for x in master_key}

        self.assertEqual(32, len(master_key))
        self.assertTrue(all(freq.values()))

    def test_crypto_kdf_derive_from_key(self):

        master_key = kda.crypto_kdf_keygen()
        subkey = kda.crypto_kdf_derive_from_key(
            16, 1, "Examples", master_key)
        subkey2 = kda.crypto_kdf_derive_from_key(
            16, 1, "Examples", master_key)
        subkey3 = kda.crypto_kdf_derive_from_key(
            16, 2, "Examples", master_key)

        self.assertEqual(16, len(subkey))
        self.assertEqual(16, len(subkey2))
        self.assertEqual(16, len(subkey3))
        self.assertEqual(subkey, subkey2)
        self.assertNotEqual(subkey, subkey3)

    def test_crypto_kx_keypair(self):
        pk, sk = kea.crypto_kx_keypair()
        self.assertEqual(32, len(pk))
        self.assertEqual(32, len(sk))

    def test_crypto_kx_seed_keypair(self):
        seed = rbg.randombytes_buf(32)
        seed2 = rbg.randombytes_buf(32)
        pk, sk = kea.crypto_kx_seed_keypair(seed)
        pk2, sk2 = kea.crypto_kx_seed_keypair(seed)
        pk3, sk3 = kea.crypto_kx_seed_keypair(seed2)

        self.assertEqual(pk, pk2)
        self.assertNotEqual(pk, pk3)
        self.assertEqual(sk, sk2)
        self.assertNotEqual(sk, sk3)

    def test_crypto_kx_client_session_keys(self):
        client_pk, client_sk = kea.crypto_kx_keypair()
        server_pk, server_sk = kea.crypto_kx_keypair()
        rx, tx, status = kea.crypto_kx_client_session_keys(
            client_pk, client_sk, server_pk)
        rx2, tx2, status = kea.crypto_kx_client_session_keys(
            client_pk, client_sk, server_pk)

        self.assertEqual(32, len(rx))
        self.assertEqual(32, len(tx))
        self.assertEqual(rx, rx2)
        self.assertEqual(tx, tx2)

    def test_crypto_kx_server_session_keys(self):
        client_pk, client_sk = kea.crypto_kx_keypair()
        server_pk, server_sk = kea.crypto_kx_keypair()
        rx, tx, status = kea.crypto_kx_server_session_keys(
            client_pk, client_sk, server_pk)
        rx2, tx2, status = kea.crypto_kx_server_session_keys(
            client_pk, client_sk, server_pk)

        self.assertEqual(32, len(rx))
        self.assertEqual(32, len(tx))
        self.assertEqual(rx, rx2)
        self.assertEqual(tx, tx2)
