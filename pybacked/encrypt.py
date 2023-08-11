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


# Predefined share configurations
SHARES = {"2/3": (2, 3), "3/5": (3, 5), "4/7": (4, 7)}


def password_similarity(password1: str, password2: str) -> float:
    """Calculate the similarity ratio between two passwords."""
    return SequenceMatcher(None, password1, password2).ratio()


def check_data_length(data: str) -> str:
    """
    Ensure the data length is within the limits.

    Args:
        data (str): The data to be checked.

    Returns:
        str: The validated data.
    """
    while len(bytes(data, "UTF-8")) > 128:
        data = click.prompt(
            text="[ERROR] Data must be less than 128 bytes. You can use other containers. Data to encrypt",
            type=str,
        )
    return data


def generate_qr_code(data: str, name: str) -> None:
    """
    Generate a QR code for the provided data and save it as an image.

    Args:
        data (str): The data to be encoded in the QR code.
        name (str): The base name for the output image file.
    """
    qrcode.make(data).save(f"{name}_{hexlify(get_random_bytes(8)).decode()}.png")


@click.command()
def encrypt() -> None:
    """
    Encrypt data using secret sharing and generate QR code shares.

    This function provides a command-line interface for encrypting data using secret sharing. Users can specify the
    number of shares and the amount of containers to be encrypted. The encrypted shares are then generated as QR codes.
    """
    share = click.prompt(text="Choose amount of shares", type=click.Choice(SHARES))
    data: str = check_data_length(
        click.prompt(text="Data to encrypt (128 bytes)", type=str)
    )
    password: str = click.prompt(
        text="Password", confirmation_prompt=True, hide_input=True
    )
    containers = [ContainerData(data=data.encode(), password=password)]
    for c in range(2, 4):
        if click.confirm(
            f"Do you want to add data to hidden container №{c}? (It will create separate container with its own password)"
        ):
            new_data: str = check_data_length(
                click.prompt(text="Data to encrypt (128 bytes)")
            )
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
                    text="[ERROR] The password must be at least 70% different from the others. Password",
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
