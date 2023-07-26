from binascii import hexlify, unhexlify
from typing import List
from Crypto.Random import get_random_bytes
from dataclasses import dataclass
from models import ShareModel, Information, Container, Header

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
        containers: tuple[ContainerData, ContainerData, ContainerData],
    ) -> None:
        self.id = hexlify(get_random_bytes(8))
        self.shares_amount = shares_amount
        self.__containers = containers
        self.information = self._encrypt_containers()
        self.encoder = Encoder(self.information.model_dump_json().encode("UTF-8"))

    def _encrypt_containers(self) -> Information:
        return Information(
            containers=[
                Container(
                    data=aes_encrypt(container.data, hash_password(container.password))
                )
                for container in self.__containers
            ]
        )

    def _get_shares(self) -> List[Header]:
        return [
            Header(share=share, id=self.id, threshold=self.shares_amount[0])
            for share in self.encoder.shamir_split(self.shares_amount)
        ]

    def _collect_containers(self) -> bytes:
        return self.encoder.encrypt_data()

    def assemble(self) -> List[str]:
        information = self._collect_containers()
        return [
            ShareModel(header=header, information=information).model_dump_json()
            for header in self._get_shares()
        ]
