from setuptools import setup, find_packages
from keyops import version

setup(
        name="keyops", 
        version=version,
        author="Christoph Winter",
        author_email="cheesemid@protonmail.com",
        description="Easy cryptographic operations",
        long_description="Easy cryptographic operations. Includes RSA, AES and SHA1 TOTP.",
        url="https://github.com/cheesemid/keyops",
        packages=find_packages(),
        install_requires=["qrcode", #qrcode==6.1
                                    ],
        
        keywords=[],
        classifiers= [
            f"Development Status :: Version {version}",
            "Programming Language :: Python :: 3",
            "Operating System :: Microsoft :: Windows",
            "Operating System :: Linux",
        ]
)