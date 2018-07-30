# Alex Daigre Andrew Dillon Neil Eichelberger Archie McClendon
# === Task 4 ===
# Create 2 different sized files, encrypt them with AES with 128
# and 256 bit keys.  Generate key randomly
# determine how many times you can encrypt and decrypt a file a
# second with various settings.  Then repeat the above using RSA,
# how large a file could you decrypt in a second?
# https://cryptography.io/en/latest/fernet/


from __future__ import print_function, unicode_literals
import struct
import math
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes)
from binascii import unhexlify
import os
from os import urandom
import base64
import time
import sys

""" CREATE FILES TO ENCRYPT <-> DECRYPT """
content = bytes('\0','utf-8')
with open('textFile01.txt','wb') as out:
    out.seek((1000000) -1) #1000000 bytes 100kb
    out.write(content)
with open('textFile02.txt','wb') as out:
    out.seek((5000000) -1) #5000000 bytes 500kb
    out.write(content)

print('\n##### Task 4 : Project 2 #####\n')

#############

def encrypt128(ptext):
    """ AES encrypt CBC Mode 128 bit key """
    pad = padding.PKCS7(128).padder()
    ptext = pad.update(ptext) + pad.finalize()

    alg = algorithms.AES(key)
    mode = modes.CBC(iv)
    cipher = Cipher(alg, mode, backend=backend)
    encryptor = cipher.encryptor()
    ctext = encryptor.update(ptext) + encryptor.finalize()
    return ctext

def encrypt256(ptext):
    """ AES encrypt CBC Mode 256 bit key """
    pad = padding.PKCS7(256).padder()
    ptext = pad.update(ptext) + pad.finalize()

    alg = algorithms.AES(key)
    mode = modes.CBC(iv)
    cipher = Cipher(alg, mode, backend=backend)
    encryptor = cipher.encryptor()
    ctext = encryptor.update(ptext) + encryptor.finalize()
    return ctext

def decrypt128(key, iv, ctext):
    """ AES decrypt CBC Mode 128 bit key """
    alg = algorithms.AES(key)
    mode = modes.CBC(iv)
    cipher = Cipher(alg, mode, backend=backend)
    decryptor = cipher.decryptor()
    ptext = decryptor.update(ctext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder() # 128 bit
    ptext = unpadder.update(ptext) + unpadder.finalize()
    return ptext

def decrypt256(key, iv, ctext):
    """ AES decrypt CBC Mode 256 bit key """
    alg = algorithms.AES(key)
    mode = modes.CBC(iv)
    cipher = Cipher(alg, mode, backend=backend)
    decryptor = cipher.decryptor()
    ptext = decryptor.update(ctext) + decryptor.finalize()
    unpadder = padding.PKCS7(256).unpadder() # 256 bit
    ptext = unpadder.update(ptext) + unpadder.finalize()
    return ptext

####################

input("Press Enter to continue...")
backend = default_backend()

""" First Run """
counter01 = 0
key = os.urandom(16)
iv = os.urandom(16)
t_end = time.time() + 1
while time.time() < t_end:
    """ Run first file AES with 128bit key """
    with open('textFile01.txt', 'rb') as f:
        plaintext = f.read()
    ciphertext = encrypt128(plaintext)
    
    with open('textFile01.txt_enc', 'wb') as f:
        f.write(ciphertext)
    
    with open('textFile01.txt_enc', 'rb') as f:
         ciphertext = f.read()         
    plaintext = decrypt128(key, iv, ciphertext)
    counter01 += 1
    f.close()
print('--> AES CBC Mode 100kb file 128bit key encrypt->decrypt completed: ' + str(counter01) + '.')

input("Press Enter to continue...")

""" Second Run """
counter02 = 0
key = os.urandom(16)
iv = os.urandom(16)
t_end = time.time() + 1
while time.time() < t_end:
    """ Run second file AES with 128bit key """
    with open('textFile02.txt', 'rb') as f:
        plaintext = f.read()
    ciphertext = encrypt128(plaintext)
    with open('textFile02.txt_enc', 'wb') as f:
        f.write(ciphertext)
    with open('textFile02.txt_enc', 'rb') as f:
        ciphertext = f.read()
    plaintext = decrypt128(key, iv, ciphertext)
    counter02 += 1
    f.close()
print('--> AES CBC Mode 500kb file 128bit key encrypt->decrypt completed: ' + str(counter02) + '.')

input("Press Enter to continue...")

""" Third Run """
counter03 = 0
key = os.urandom(32)
iv = os.urandom(16)
t_end = time.time() + 1
while time.time() < t_end:
    """ Run first file AES with 256bit key """
    with open('textFile01.txt', 'rb') as f:
        plaintext = f.read()
    ciphertext = encrypt256(plaintext)
    with open('textFile01.txt_enc', 'wb') as f:
        f.write(ciphertext)
    with open('textFile01.txt_enc', 'rb') as f:
         ciphertext = f.read()         
    plaintext = decrypt256(key, iv, ciphertext)
    counter03 += 1
    f.close()
print('--> AES CBC Mode 100kb file 256bit key encrypt->decrypt completed: ' + str(counter03) + '.')

input("Press Enter to continue...")

""" Fourth Run """
counter04 = 0
key = os.urandom(32)
iv = os.urandom(16)
t_end = time.time() + 1
while time.time() < t_end:
    """ Run second file AES with 256bit key """
    with open('textFile02.txt', 'rb') as f:
        plaintext = f.read()
    ciphertext = encrypt256(plaintext)
    with open('textFile02.txt_enc', 'wb') as f:
        f.write(ciphertext)
    with open('textFile02.txt_enc', 'rb') as f:
         ciphertext = f.read()         
    plaintext = decrypt256(key, iv, ciphertext)
    counter04 += 1
    f.close()
print('--> AES CBC Mode 500kb file 256bit key encrypt->decrypt completed: ' + str(counter04) + '.')

time.sleep(1)
input("Press Enter to continue...")

########## RSA ############
#### sudo pip3 install pycrypto
#### sudo pip3 install pycryptodome
#### sudo pip3 install cryptography

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils


def gen_key():
    """ RSA private key """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    return private_key
def gen_pubKey(privateKey):
    """ RSA PUBLIC KEY """
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash, default_backend())
    hasher.update(b"data & ")
    hasher.update(b"more data")
    digest = hasher.finalize()
    sig = privateKey.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
        utils.Prehashed(chosen_hash)
        )    
    publicKey = privateKey.public_key()
    publicKey.verify(
        sig,
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
        utils.Prehashed(chosen_hash)
        )
    return publicKey

def encryptRSA(public_key, message):
    """ RSA ENCRYPT """
    cText = public_key.encrypt(
        message, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
    return cText

def decryptRSA(private_key, ciphertext):
    """ RSA DECRYPT """
    pText = private_key.decrypt(
        ciphertext,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )    
    return pText

### CREATE FILES FOR RSA ###
f = open('rsaFile1','wb')
f.seek(15) #16byte
f.write(b"\0")
f.close()

f = open('rsaFile2','wb')
f.seek(31) #32byte
f.write(b"\0")
f.close()

f = open('rsaFile3','wb')
f.seek(63) #64byte
f.write(b"\0")
f.close()

f = open('rsaFile4','wb')
f.seek(127) #64byte
f.write(b"\0")
f.close()

n1 = 0
ti_end = time.time() + 1
while time.time() < ti_end:
    with open('rsaFile1', 'rb') as f:
        plaintext = f.read()
    privateKey = gen_key()
    publicKey = gen_pubKey(privateKey)
    t1 = encryptRSA(publicKey, plaintext)
    t2 = decryptRSA(privateKey,t1)
    n1 += 1                  
print("--> RSA Encryption on 16 byte file: Encrypt->Decrypt operations completed: " + str(n1) +".")

input("Press Enter to continue...")

n2 = 0
t2_end = time.time() + 1
while time.time() < t2_end:
    with open('rsaFile2', 'rb') as f:
        plaintext = f.read()
    privateKey = gen_key()
    publicKey = gen_pubKey(privateKey)
    t1 = encryptRSA(publicKey, plaintext)
    t2 = decryptRSA(privateKey,t1)
    n2 += 1                  
print("--> RSA Encryption on 32 byte file: Encrypt->Decrypt operations completed: " + str(n2) +".")

input("Press Enter to continue...")

n3 = 0
t3_end = time.time() + 1
while time.time() < t3_end:
    with open('rsaFile3', 'rb') as f:
        plaintext = f.read()
    privateKey = gen_key()
    publicKey = gen_pubKey(privateKey)
    t1 = encryptRSA(publicKey, plaintext)
    t2 = decryptRSA(privateKey,t1)
    n3 += 1                  
print("--> RSA Encryption on 64 byte file: Encrypt->Decrypt operations completed: " + str(n3) +".")

input("Press Enter to continue...")

n4 = 0
t4_end = time.time() + 1
while time.time() < t4_end:
    with open('rsaFile4', 'rb') as f:
        plaintext = f.read()
    privateKey = gen_key()
    publicKey = gen_pubKey(privateKey)
    t1 = encryptRSA(publicKey, plaintext)
    t2 = decryptRSA(privateKey,t1)
    n3 += 1                  
print("--> RSA Encryption on 128 byte file: Encrypt->Decrypt operations completed: " + str(n4) +".\n")
