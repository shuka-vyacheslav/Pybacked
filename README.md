# Pybacked

[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)](https://python-poetry.org/)
[![GitHub license](https://img.shields.io/github/license/Naereen/StrapDown.js.svg)](https://github.com/shuka-vyacheslav/Pybacked/blob/main/LICENSE)

FOSS CLI clone of [Superbacked](https://superbacked.com/).

The script creates three encrypted containers with different passwords, after which they are combined, encrypted again and divided into several parts as QR codes. Only a fraction of the shares is sufficient for recovery. The program uses Shamir secret sharing and AES encryption.

## Quick start

This project uses [Poetry](https://github.com/python-poetry/poetry). Also, this project uses the zbar package. If you are using Windows it is already installed, on Linux and macOS **you need to install it manually**.

```console
$ poetry shell
$ poetry install
```

## Encryption

```console
$ ./encrypt.py
Choose amount of shares (2/3, 3/5, 4/7): 2/3
Data to encrypt (128 bytes): Secret №1
Password:
Repeat for confirmation:
Do you want to add data to hidden container №2? (It will create separate container with its own password) [y/N]: y
Data to encrypt (128 bytes): Secret №2
Password:
Repeat for confirmation:
Do you want to add data to hidden container №3? (It will create separate container with its own password) [y/N]: N
```

The output will give you three QR codes, any two of which will be enough to decode.

## Decryption
```console
$ ./decrypt.py
Enter the path to the image containing the QR code: 8172e01730e17ae4_72cedb5119d07656.png
Enter the path to the image containing the QR code: 8172e01730e17ae4_b94823f28ab535d0.png
Password: 
Are you sure no one can see your secret? [y/N]: y
Secret №1
Password: 
Are you sure no one can see your secret? [y/N]: y
Secret №2
```