import argparse
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def create_key(password):
    bpass = password.encode('utf-8')
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=b"20200915",
                     iterations=100000,
                     backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(bpass))
    return key


def decrypt(edata, password):
    key = create_key(password)
    fn = Fernet(key)
    plain_data = fn.decrypt(edata)
    return plain_data


def encrypt(data, password):
    key = create_key(password)
    fn = Fernet(key)
    crypt_data = fn.encrypt(data)
    return crypt_data

def decrypt_from_file(infile, password):
    with open(infile, "rb") as encry:
        data = encry.read()
    decrypted = decrypt(data, password)
    return decrypted
