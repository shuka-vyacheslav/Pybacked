#!/usr/bin/env python3
import sys
import click
from pyzbar.pyzbar import decode
from PIL import Image, UnidentifiedImageError

from pybacked.handlers.disassembler import Disassembler
from pybacked.handlers.exceptions import NotValidSharesError


def decode_qr() -> str:
    """
    Decode a QR code image and return the decoded data.

    Returns:
        str: The decoded data from the QR code image.
    """
    while True:
        try:
            path = click.prompt(
                text="Enter the path to the image containing the QR code",
                type=click.Path(
                    exists=True, file_okay=True, dir_okay=False, readable=True
                ),
            )
            data = decode(Image.open(path))
            return data[0].data.decode("UTF-8")
        except UnidentifiedImageError:
            click.echo(message="[ERROR] Use a QR code image file")


def decrypt_with_password(disassembler: Disassembler, password: str) -> str:
    """
    Decrypt a container using a password.

    Args:
        disassembler (Disassembler): The Disassembler instance containing the shares.
        password (str): The password used for decryption.

    Returns:
        str: The decrypted data.
    """
    try:
        return disassembler.decrypt_container(password=password).decode("UTF-8")
    except NotValidSharesError:
        click.echo(message="[ERROR] Password is incorrect")
        sys.exit(0)


@click.command()
def decrypt() -> None:
    """
    Decrypt secret data using QR code shares and a password.

    This function provides a command-line interface to guide users through the process of decrypting secret data using QR
    code shares and a password. It decodes the shares, validates them, prompts for the password, decrypts the data, and
    displays the decrypted content.
    """
    shares = [decode_qr()]
    while True:
        try:
            threshold = Disassembler.get_threshold(shares[0])
            break
        except IndexError:
            click.echo(message="[ERROR] The resulting code cannot be interpreted")
    for _ in range(threshold - 1):
        shares.append(decode_qr())
    try:
        disassembler = Disassembler(shares=shares)
    except NotValidSharesError:
        click.echo(message="[ERROR] The resulting shares cannot be interpreted")
        sys.exit(0)
    while True:
        password: str = click.prompt(
            text="Password", confirmation_prompt=False, hide_input=True
        )
        data = decrypt_with_password(disassembler=disassembler, password=password)
        if click.confirm("Are you sure no one can see your secret?"):
            click.echo(data)
        else:
            sys.exit(0)


if __name__ == "__main__":
    decrypt()
