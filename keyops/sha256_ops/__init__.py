#!/usr/bin/env python3

from hashlib import sha256

def hash(input_message, returnhex=True):
    if isinstance(input_message, str):
        input_message_bytes = input_message.encode("utf-8")
    elif isinstance(input_message, bytes):
        input_message_bytes = input_message
    else:
        raise Exception("Input_message must be of type str or bytes")

    sha = sha256()
    sha.update(input_message_bytes)
    if returnhex:
        return sha.hexdigest()
    return sha.digest()

def validate(input_message, hashed_message):
    if isinstance(input_message, str):
        input_message_bytes = input_message.encode("utf-8")
    elif isinstance(input_message, bytes):
        input_message_bytes = input_message
    else:
        raise Exception("Input_message must be of type str or bytes")

    if isinstance(hashed_message, str):
        hashed_message_bytes = bytes.fromhex(hashed_message)
    elif isinstance(hashed_message, bytes):
        hashed_message_bytes = hashed_message
    else:
        raise Exception("Hashed_message must be of type str or bytes")

    sha = sha256()
    sha.update(input_message_bytes)

    return sha.digest() == hashed_message_bytes