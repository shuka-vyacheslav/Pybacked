from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2

from pybacked.secret_sharing.exceptions import NotValidKeyError


def hash_password(password: str, salt: bytes) -> bytes:
    """
    Hashes a password using PBKDF2 and SHA-512.

    Args:
        password (str): The password to be hashed.

    Returns:
        bytes: The hashed password.
    """
    salt = unhexlify(salt)
    return PBKDF2(password, salt, 16, count=1_000_000, hmac_hash_module=SHA512)


def aes_encrypt(data: bytes, key: bytes) -> bytes:
    """
    Encrypts data using AES.

    Args:
        data (bytes): The data to be encrypted.
        key (bytes): The encryption key used for AES encryption.

    Returns:
        bytes: The encrypted data in hexadecimal format (nonce + tag + ciphertext).
    """
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return hexlify(nonce + tag + ciphertext)


def aes_decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypts data using AES decryption.

    Args:
        encrypted_data (bytes): The encrypted data in hexadecimal format (nonce + tag + ciphertext).
        key (bytes): The decryption key used for AES decryption.

    Returns:
        bytes: The original decrypted data.

    Raises:
        NotValidKeyError: If the provided key is not valid for decrypting the data.
    """
    encrypted_data = unhexlify(encrypted_data)
    nonce, tag, ciphertext = (
        encrypted_data[:16],
        encrypted_data[16:32],
        encrypted_data[32:],
    )
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise NotValidKeyError
    return data
