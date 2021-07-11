#!/usr/bin/env python3

# Utility for Google Authenticator Compatible TOTP Tokens
# 041321 zed

import os
import time
import base64
import qrcode
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.hazmat.primitives.hashes import SHA1, SHA256

def create(keylen=20, key=b""):
    """
    Keylen should be a minimum of 20 bytes
    """
    assert(isinstance(keylen,int))
    assert(isinstance(key,bytes))
    if key == b"":
        key = os.urandom(keylen)
    elif len(key) < 20:
        return 1
    totp = TOTP(key, 6, SHA1(), 30) # G Authenticator will only work with this configuration
    return (totp, key)

def gettoken(totp):
    time_value = int(time.time())
    totp_value = totp.generate(time_value)
    totp.verify(totp_value, time_value)
    return int(totp_value.decode("utf-8"))

def verifytoken(token, totp):
    time_value = time.time()
    ftoken = b""
    if isinstance(token, int) or isinstance(token, str):
        ftoken = str(token).encode("utf-8")
    elif isinstance(token, bytes):
        ftoken = token
    try:
        totp.verify(ftoken, time_value)
        return True
    except:
        return False

def verifyattime(token, time, totp):
    if isinstance(time, str):
        time_value = int(time, 16) #allow input of hex representation of unix time
    else:
        time_value = int(time)
    ftoken = b""
    if isinstance(token, int) or isinstance(token, str):
        ftoken = str(token).encode("utf-8")
    elif isinstance(token, bytes):
        ftoken = token
    try:
        totp.verify(ftoken, time_value)
        return True
    except:
        return False

def geturi(account_name, issuer_name, totp):
    uri = totp.get_provisioning_uri(account_name, issuer_name) # G Authenticator displays as "issuer_name (account_name)"
    return uri

def makeqrcode(account_name, issuer_name, totp, filepath=""):
    uri = geturi(account_name, issuer_name, totp)
    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    if filepath != "":
        img.save(filepath)
    return img


