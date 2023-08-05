from binascii import hexlify
from random import randrange
from typing import List
from Crypto.Random import get_random_bytes
from dataclasses import dataclass
from .models import ShareModel, Information, Container, Header

from pybacked.handlers.aes import aes_encrypt, hash_password
from pybacked.secret_sharing.shamir import Encoder


@dataclass
class ContainerData:
    data: bytes
    password: str


class Assembler:
    def __init__(
        self,
        shares_amount: tuple[int, int],
        containers: tuple[ContainerData, ContainerData | None, ContainerData | None],
    ) -> None:
        """
        Constructor for the Assembler class.

        Parameters:
            shares_amount (tuple[int, int]): A tuple containing the threshold and total number of shares.
            The first element is the threshold (minimum number of shares required
            to reconstruct the secret), and the second element is the total number
            of shares to be generated.
            containers (tuple[ContainerData, ContainerData, ContainerData]): A tuple containing three ContainerData
            instances, each representing the data and password for a container.
        """
        self.id = hexlify(get_random_bytes(8))
        self.shares_amount = shares_amount
        self.__containers = containers
        self.__salt = hexlify(get_random_bytes(16))
        self.information = self._encrypt_containers()
        self.encoder = Encoder(self.information.model_dump_json().encode("UTF-8"))

    def _encrypt_containers(self) -> Information:
        """
        Encrypts containers using AES encryption.

        Returns:
            Information: An Information object containing encrypted containers.
        """
        return Information(
            salt=self.__salt,
            containers=[
                Container(
                    data=aes_encrypt(
                        data=container.data,
                        key=hash_password(
                            password=container.password, salt=self.__salt
                        ),
                    )
                )
                if container
                else Container(
                    data=hexlify(
                        get_random_bytes(randrange(3, 128))
                    )  # TODO: calculate maximum capacity for container
                )
                for container in self.__containers
            ],
        )

    def _get_shares(self) -> List[Header]:
        """
        Generates Shamir's Secret Sharing shares for the encrypted containers.

        Returns:
            List[Header]: A list of Header objects, each representing a share with its associated metadata.
        """
        return [
            Header(share=share, id=self.id, threshold=self.shares_amount[0])
            for share in self.encoder.shamir_split(self.shares_amount)
        ]

    def _collect_containers(self) -> bytes:
        """
        Collects the encrypted containers and combines them into a single binary.

        Returns:
            bytes: The binary containing the encrypted containers.
        """
        return self.encoder.encrypt_data()

    def assemble(self) -> List[str]:
        """
        Assembles and prepares the shares along with their associated information for distribution.

        Returns:
            List[str]: A list of JSON-serialized ShareModel objects, each representing a share with its associated
            encrypted information.
        """
        information = self._collect_containers()
        return [
            ShareModel(header=header, information=information).model_dump_json()
            for header in self._get_shares()
        ]
