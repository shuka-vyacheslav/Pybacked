#!/usr/bin/env python3
import click
from difflib import SequenceMatcher
import qrcode

from pybacked.handlers.assembler import (
    ContainerData,
    Assembler,
    hexlify,
    get_random_bytes,
)


SHARES = {"2/3": (2, 3), "3/5": (3, 5), "4/7": (4, 7)}


def password_similarity(password1: str, password2: str) -> float:
    return SequenceMatcher(None, password1, password2).ratio()


def generate_qr_code(data: str, name: str) -> None:
    qrcode.make(data).save(f"{name}_{hexlify(get_random_bytes(8))}.png")


@click.command()
def encrypt() -> None:
    share = click.prompt(text="Choose amount of shares", type=click.Choice(SHARES))
    data: str = click.prompt(text="Data to encrypt", type=str)
    password: str = click.prompt(
        text="Password", confirmation_prompt=True, hide_input=True
    )
    containers = [ContainerData(data=data.encode(), password=password)]
    for c in range(2, 4):
        if click.confirm(
            f"Do you want to add data to hidden container №{c}? (It will create separate container with its own password)"
        ):
            new_data: str = click.prompt(text="Data to encrypt")
            new_password: str = click.prompt(
                text="Password", confirmation_prompt=True, hide_input=True
            )

            while (
                max(
                    map(
                        lambda x: password_similarity(x.password, new_password),
                        containers,
                    )
                )
                > 0.3
            ):
                new_password = click.prompt(
                    text="The password must be at least 70% different from the others. Password",
                    confirmation_prompt=True,
                    hide_input=True,
                )
            containers.append(
                ContainerData(data=new_data.encode(), password=new_password)
            )
        else:
            containers.append(None)
            break
    assembler = Assembler(shares_amount=SHARES[share], containers=tuple(containers))
    shares = assembler.assemble()
    for share in shares:
        generate_qr_code(data=share, name=assembler.id.decode())


if __name__ == "__main__":
    encrypt()
