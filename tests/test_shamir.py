import unittest
from binascii import unhexlify
from pybacked.secret_sharing.exceptions import NotValidKeyError
from pybacked.secret_sharing.shamir import Encoder, Decoder, Share


class TestEncoderAndDecoder(unittest.TestCase):
    def test_encoder_and_decoder(self):
        # Test data to be encrypted
        data = b"Hello, this is a secret message!"

        # Create an Encoder instance and encrypt the data
        encoder = Encoder(data)
        encrypted_data = encoder.encrypt_data()

        # Generate shares using Shamir secret sharing
        shares_amount = (3, 5)  # Threshold of 3 and total shares of 5
        shares = encoder.shamir_split(shares_amount)

        # Create a Decoder instance with the shares and decrypt the data
        decoder = Decoder(shares)
        decrypted_data = decoder.decrypt_data(encrypted_data)

        # Verify that the decrypted data matches the original data
        self.assertEqual(decrypted_data, data)

    def test_invalid_decryption(self):
        # Test decryption with an invalid key (wrong shares)
        data = b"Hello, this is a secret message!"
        encoder = Encoder(data)
        encrypted_data = encoder.encrypt_data()

        # Generate shares using Shamir secret sharing
        shares_amount = (3, 5)  # Threshold of 3 and total shares of 5
        shares = encoder.shamir_split(shares_amount)

        # Create an unrelated Decoder instance with wrong shares
        invalid_shares = [
            Share(index=i, hex=unhexlify(b"0123456789ABCDEF")) for i in range(1, 6)
        ]
        decoder = Decoder(invalid_shares)

        with self.assertRaises(NotValidKeyError):
            decoder.decrypt_data(encrypted_data)

    def test_not_enough_shares(self):
        # Test decryption with not enough shares
        data = b"Hello, this is a secret message!"
        encoder = Encoder(data)
        encrypted_data = encoder.encrypt_data()

        # Generate shares using Shamir secret sharing
        shares_amount = (5, 8)  # Threshold of 5 and total shares of 8
        shares = encoder.shamir_split(shares_amount)

        # Keep only 3 shares instead of the required 5
        insufficient_shares = shares[:3]

        # Create a Decoder instance with fewer shares and attempt decryption
        decoder = Decoder(insufficient_shares)

        with self.assertRaises(NotValidKeyError):
            decoder.decrypt_data(encrypted_data)


if __name__ == "__main__":
    unittest.main()
