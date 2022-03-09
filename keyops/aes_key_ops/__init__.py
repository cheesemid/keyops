import os
from turtle import back
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC

def encrypt(message, key):
    if not isinstance(message, bytes):
        bmessage = str(message).encode("utf-8")
    else:
        bmessage = message    

    bmessage = __pad(bmessage)

    iv = os.urandom(16)
    cipher = Cipher(AES(key), CBC(iv), backend=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(bmessage) + encryptor.finalize()
    return (ciphertext, iv)

def decrypt(ciphertext, iv, key):
    cipher = Cipher(AES(key), CBC(iv))
    decryptor = cipher.decryptor()
    paddedplaintext = decryptor.update(ciphertext) + decryptor.finalize()

    plaintext = __depad(paddedplaintext)

    return plaintext

def __pad(msg):
    # pad with random bytes until msg%16==0 and set last byte to number of padding bytes eg: ... ... 3f 5d e6 28 9c ab  06
    padlen = 16 - ((len(msg) - 1) % 16) - 1
    if padlen != 0:
        padding = os.urandom(padlen - 1)
    else:
        padding = os.urandom(15)
        padlen = 16

    return msg + padding + bytes([padlen])

def __depad(msg):
    # remove padding based on the last byte
    padlen = int.from_bytes(msg[-1:],byteorder='little')
    return msg[:-padlen]