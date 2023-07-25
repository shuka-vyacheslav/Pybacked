from binascii import hexlify, unhexlify
from dataclasses import dataclass
from pydoc import stripid
from typing import List
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir


@dataclass
class Share:
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
            for i, h in Shamir.split(*shares_amount, self.__key, ssss=True)
        ]

    def encrypt_data(self) -> bytes:
        """
        Encrypts the data using AES.

        Returns:
            bytes: The encrypted data in hexadecimal format.
        """
        cipher = AES.new(self.__key, AES.MODE_EAX)
        ct, tag = cipher.encrypt(self.data), cipher.digest()
        return hexlify(cipher.nonce + tag + ct)
