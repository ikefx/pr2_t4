# === Task 4 ===
# Create 2 different sized files, encrypt them with AES with 128
# and 256 bit keys.  Generate key randomly
# determine how many times you can encrypt and decrypt a file a
# second with various settings.  Then repeat the above using RSA,
# how large a file could you decrypt in a second?
# https://cryptography.io/en/latest/fernet/

from __future__ import print_function, unicode_literals
import struct
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import padding
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
import sched
import itertools
import sys

""" CREATE FILES TO ENCRYPT <-> DECRYPT """
content = bytes('\0','utf-8')
with open('textFile01.txt','wb') as out:
    out.seek((125000) -1)
    out.write(content)
with open('textFile02.txt','wb') as out:
    out.seek((4000000) -1)
    out.write(content)

print('\n##### Task 4 : Project 2 #####\n')

#############

def encrypt128(ptext):
    """ AES encrypt CBC Mode 128 bit key """
    backend = default_backend()
    iv = os.urandom(16)

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
print('AES CBC Mode with 128 bit key on small: \"textFile01.txt\" encrypted-->decrypted ' + str(counter01) + ' times.')

#time.sleep(1)

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
print('AES CBC Mode with 128 bit key on big: \"textFile02.txt\" encrypted-->decrypted ' + str(counter02) + ' times.')

#time.sleep(1)

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
print('AES CBC Mode with 256 bit key on small: \"textFile01.txt\" encrypted-->decrypted ' + str(counter03) + ' times.')
#time.sleep(1)

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
print('AES CBC Mode with 256 bit key on big: \"textFile02.txt\" encrypted--> ' + str(counter04) + ' times.')
