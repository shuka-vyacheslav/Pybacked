from binascii import hexlify, unhexlify, Error
from dataclasses import dataclass
from typing import List
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
from pydantic import BaseModel

from pybacked.handlers.aes import aes_encrypt, aes_decrypt
from pybacked.secret_sharing.exceptions import NotValidKeyError


class Share(BaseModel):
    """
    Represents the share of the secret received after splitting or from the user.

    Attributes:
        index (int): The index of the share.
        hex (str): The hexadecimal representation of the share.
    """

    index: int
    hex: bytes


class Encoder:
    """
    A class for encrypting data using Shamir secret sharing and AES.

    Attributes:
        data (bytes): The data to be encoded and encrypted.
        __key (bytes): The private key used for AES encryption.
    """

    def __init__(self, data: bytes) -> None:
        self.__key = get_random_bytes(16)
        self.data = data

    def shamir_split(self, shares_amount: tuple[int, int]) -> List[Share]:
        """
        Splits the private key using Shamir secret sharing algorithm.

        Args:
            shares_amount (tuple[int, int]): A tuple representing the threshold and total number of shares to generate.

        Returns:
            List[Share]: A list of Share objects containing the shares of the secret.
        """
        return [
            Share(index=i, hex=hexlify(h))
            for i, h in Shamir.split(*shares_amount, self.__key, ssss=False)
        ]

    def encrypt_data(self) -> bytes:
        """
        Encrypts the data using AES.

        Returns:
            bytes: The encrypted data in hexadecimal format.
        """
        return aes_encrypt(self.data, self.__key)


class Decoder:
    """
    A class for decrypting data using Shamir secret sharing and AES.

    Attributes:
        shares (List[Share]): A list of Share objects containing the shares of the secret.
    """

    def __init__(self, shares: List[Share]) -> None:
        self.shares = shares

    def _shamir_combine(self) -> bytes:
        """
        Combines the shares in a key using Shamir's secret sharing algorithm.

        Returns:
            bytes: The original secret key used for AES decryption.
        """
        try:
            key = [(share.index, unhexlify(share.hex)) for share in self.shares]
        except Error:
            raise NotValidKeyError
        return Shamir.combine(key, ssss=False)

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Decrypts the data using AES.

        Args:
            encrypted_data (bytes): The encrypted data in hexadecimal format (nonce + tag + ciphertext).

        Returns:
            bytes: The original decrypted data.
        """
        key = self._shamir_combine()
        data = aes_decrypt(encrypted_data, key)
        return data
