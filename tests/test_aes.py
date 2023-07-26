import unittest
from Crypto.Random import get_random_bytes

from pybacked.secret_sharing.aes import aes_decrypt, aes_encrypt, hash_password
from pybacked.secret_sharing.exceptions import NotValidKeyError


class TestAES(unittest.TestCase):
    def test_hash_password(self):
        # Test password hashing
        password = "secure_password"
        hashed_password = hash_password(password)
        self.assertIsInstance(hashed_password, bytes)

    def test_aes_encrypt_and_decrypt(self):
        # Test AES encryption and decryption with valid key
        data = b"Hello, this is a secret message!"
        password = "super_secret_password"
        hashed_password = hash_password(password)
        key = hashed_password[:16]  # AES key should be 16 bytes long

        encrypted_data = aes_encrypt(data, key)
        self.assertIsInstance(encrypted_data, bytes)

        decrypted_data = aes_decrypt(encrypted_data, key)
        self.assertEqual(decrypted_data, data)

    def test_aes_decrypt_with_invalid_key(self):
        # Test AES decryption with an invalid key
        data = b"Hello, this is a secret message!"
        password = "super_secret_password"
        hashed_password = hash_password(password)
        # Generate a random key different from the encryption key
        invalid_key = get_random_bytes(16)
        while invalid_key == hashed_password:
            invalid_key = get_random_bytes(16)

        encrypted_data = aes_encrypt(data, hashed_password)

        # Attempt to decrypt with the invalid key
        with self.assertRaises(NotValidKeyError):
            aes_decrypt(encrypted_data, invalid_key)


if __name__ == "__main__":
    unittest.main()
