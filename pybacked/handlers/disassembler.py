import json
from typing import List
from models import ShareModel, Information

from pybacked.handlers.aes import aes_decrypt, hash_password, NotValidKeyError
from pybacked.secret_sharing.shamir import Decoder
from pybacked.handlers.exceptions import NotValidSharesError


class Disassembler:
    def __init__(self, shares: List[dict]) -> None:
        self.shares = [ShareModel(**share) for share in shares]
        if not self.check_shares():
            raise NotValidSharesError
        self.__containers = self._decrypt_shares()

    def check_shares(self) -> bool:
        """
        Check whether the received shares are valid for reconstruction.

        Parameters:
            shares (List[Header]): A list of Header objects representing the received shares.

        Returns:
            bool: True if all the shares have the same ID and the number of shares is equal to the threshold;
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
        decoder = Decoder([share.header.share for share in self.shares])
        decrypted_containers = json.loads(
            decoder.decrypt_data(self.shares[0].information)
        )
        return Information.model_validate(decrypted_containers)

    def decrypt_container(self, password: str) -> bytes:
        for container in self.__containers.containers:
            try:
                return aes_decrypt(container.data, hash_password(password))
            except NotValidKeyError:
                continue
        raise NotValidSharesError
