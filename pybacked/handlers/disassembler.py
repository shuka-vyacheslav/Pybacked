import json
from typing import List
from .models import ShareModel, Information

from pybacked.handlers.aes import aes_decrypt, hash_password, NotValidKeyError
from pybacked.secret_sharing.shamir import Decoder
from pybacked.handlers.exceptions import NotValidSharesError


class Disassembler:
    def __init__(self, shares: List[str]) -> None:
        """
        Initializes the Disassembler with the received shares and reconstructs the data containers.

        Args:
            shares (List[str]): A list of strings representing the received shares in JSON format.

        Raises:
            NotValidSharesError: If the received shares are not valid for reconstruction.
        """
        self.shares = [json.loads(share) for share in shares]
        self.shares = [ShareModel(**share) for share in self.shares]
        if not self.check_shares():
            raise NotValidSharesError
        self.__containers = self._decrypt_shares()

    def check_shares(self) -> bool:
        """
        Check whether the received shares are valid for reconstruction.

        Parameters:
            shares (List[Header]): A list of Header objects representing the received shares.

        Returns:
            bool: True if all the shares have the same ID and the number of shares is more or equal to the threshold;
            False otherwise.
        """
        if not self.shares:
            return False

        threshold = self.shares[0].header.threshold

        for share in self.shares:
            if share.header.id != self.shares[0].header.id:
                return False

            if share.header.threshold != threshold:
                return False

        return len(self.shares) >= threshold

    def _decrypt_shares(self) -> Information:
        """
        Decrypts the received shares and reconstructs the data containers.

        Returns:
            Information: An Information object containing the reconstructed data containers.

        Raises:
            NotValidKeyError: If the decryption key is not valid for decrypting the data.
        """
        decoder = Decoder([share.header.share for share in self.shares])
        decrypted_containers = json.loads(
            decoder.decrypt_data(self.shares[0].information)
        )
        return Information.model_validate(decrypted_containers)

    def decrypt_container(self, password: str) -> bytes:
        """
        Decrypts a data container using the provided password.

        Args:
            password (str): The password used for decrypting the data container.

        Returns:
            bytes: The decrypted data container.

        Raises:
            NotValidSharesError: If the decryption of all data containers fails using the provided password.
        """
        salt = self.__containers.salt
        for container in self.__containers.containers:
            try:
                return aes_decrypt(
                    encrypted_data=container.data,
                    key=hash_password(password, salt),
                )
            except NotValidKeyError:
                continue
        raise NotValidSharesError

    @staticmethod
    def get_threshold(data: str) -> int:
        """
        Extract the threshold value from a serialized share model data.

        Args:
            data (str): Serialized JSON data representing the share model.

        Returns:
            int: The threshold value extracted from the share model's header.
        """
        return ShareModel(**json.loads(data)).header.threshold
