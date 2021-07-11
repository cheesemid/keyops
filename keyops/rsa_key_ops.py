#!/usr/bin/env python3

# Utility for RSA Key Encryption, Decryption, Signing, Validation and SSH Format Converison
# 041321 zed

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def create(keysize=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=keysize,
        backend=default_backend()
    )
    return private_key

def savepriv(key, filename):
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

def savepub(key, filename):
    with open(filename, "wb") as f:
        if "_RSAPrivateKey" in str(type(key)):
            public_key = key.public_key()
        elif "_RSAPublicKey" in str(type(key)):
            public_key = key
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

def strpriv(key):
    return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

def strpub(key):
    if "_RSAPrivateKey" in str(type(key)):
        public_key = key.public_key()
    elif "_RSAPublicKey" in str(type(key)):
        public_key = key
    return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

def strsshpub(key):
    if "_RSAPrivateKey" in str(type(key)):
        public_key = key.public_key()
    elif "_RSAPublicKey" in str(type(key)):
        public_key = key
    return public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )

def loadpriv(filename):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key

def loadpub(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key

def loadsshpub(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_ssh_public_key(
            key_file.read()
        )
    return public_key

def loadprivfromstr(privkeystr):
    private_key = serialization.load_pem_private_key(
        privkeystr,
        password=None
    )
    return private_key

def loadpubfromstr(pubkeystr):
    public_key = serialization.load_pem_public_key(
        pubkeystr
    )
    return public_key

def loadsshpubfromstr(sshpubkeystr):
    public_key = serialization.load_ssh_public_key(
        sshpubkeystr
    )
    return public_key

def sign(inputmessage, privkey, returnhex=True):
    if isinstance(inputmessage, str):
        message = inputmessage.encode("utf-8")
    else:
        message = inputmessage

    sig = privkey.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    ),
    hashes.SHA256()
    )
    if returnhex:
        return sig.hex()
    else:
        return sig

def verify(inputmessage, inputsig, pubkey):
    if isinstance(inputmessage, str):
        message = inputmessage.encode("utf-8")
    else:
        message = inputmessage

    if isinstance(inputsig, str):
        sig = bytes.fromhex(inputsig)
    else:
        sig = inputsig

    try:
        pubkey.verify(
        sig,
        message,
        padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256()
        )
        return True
    except:
        return False

def encrypt(inputmessage, pubkey):
    if isinstance(inputmessage, str):
        message = inputmessage.encode("utf-8")
    else:
        message = inputmessage

    ciphertext = pubkey.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt(inputciphertext, privkey):
    if isinstance(inputciphertext, str):
        ciphertext = bytes.fromhex(inputciphertext)
    else:
        ciphertext = inputciphertext
    plaintext = privkey.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext