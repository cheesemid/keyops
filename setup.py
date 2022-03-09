#!/usr/bin/env python3

from setuptools import setup, find_packages
import codecs
import os.path

def read(rel_path):
    here = os.path.abspath(os.path.dirname(__file__))
    with codecs.open(os.path.join(here, rel_path), 'r') as fp:
        return fp.read()

def get_version(rel_path):
    for line in read(rel_path).splitlines():
        if line.startswith('__version__'):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    else:
        raise RuntimeError("Unable to find version string.")

__version__ = get_version("keyops/__init__.py")

setup(
        name="keyops", 
        version=__version__,
        author="Christoph Winter",
        author_email="cheesemid@protonmail.com",
        description="Easy cryptographic operations",
        long_description="Easy cryptographic operations. Includes RSA, AES, SHA256 and SHA1 TOTP.",
        url="https://github.com/cheesemid/keyops",
        packages=find_packages(),
        install_requires=["qrcode", #qrcode==6.1
                                    ],
        
        keywords=[],
        classifiers= [
            f"Development Status :: Version {__version__}",
            "Programming Language :: Python :: 3",
            "Operating System :: Microsoft :: Windows",
            "Operating System :: Linux",
        ]
)