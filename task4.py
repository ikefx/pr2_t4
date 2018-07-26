# === Task 4 ===
# Create 2 different sized files, encrypt them with AES with 128
# and 256 bit keys.  Generate key randomly
# determine how many times you can encrypt and decrypt a file a
# second with various settings.  Then repeat the above using RSA,
# how large a file could you decrypt in a second?
# https://cryptography.io/en/latest/fernet/

from cryptography.fernet import Fernet
#from Crypto.Cipher import AES
from os import urandom
import base64
import time
import itertools
import sys

print('\n##### Task 4 Project 2 #####\n')
"""
message = 'A really secret message. Not for prying eyes.'

key = Fernet.generate_key()
print(f'Key: {key}\n')

f = Fernet(key)
encrypted = f.encrypt(bytes(message, 'utf-8'))
print(f'Encrypted Message: {encrypted}\n')

decrypted = f.decrypt(encrypted).decode('utf-8')
print(f'Decrypted Message: {decrypted}\n')
"""
#500kb = 500000bytes
content = bytes('\0','utf-8')
print('##### Creating file1 of size 500kb #####')
with open('file1','wb') as out:
    out.seek((500000) -1)
    out.write(content)
print('##### Creating file2 of size 250kb #####')
with open('file2','wb') as out:
    out.seek((250000) -1)
    out.write(content)

def ut8len(s):
    return len(s.encode('utf-8'))

def create_key_128():
    """ Create a key of 128 bits """
    key = base64.urlsafe_b64encode(urandom(32))
    return key

def create_key_256():
    """ Create a key of 256 bits """
    key = base64.urlsafe_b64encode(urandom(32))
    return key

print()
key128 = create_key_128()
key256 = create_key_256()
print()
print()

""" One Second Loop """

timeout = 1
start = time.time()
"""
while (time.time() - start) - timeout:
    print ("Iteration Count: {0}".format(count))
    count += 1
    cipher_suite = Fernet(key128)
    cipher_text = cipher_suite.encrypt(b"A really secret message.  Not for prying eyes.")
"""
count = 0
for i in itertools.count():
    if time.time() - start >= timeout:
        break
    f1 = Fernet(key256)
    m1 = f1.encrypt(b"A really secret message.  Not for prying eyes.")
    m1d = f1.decrypt(m1).decode('utf-8')
    count += 1

    f2 = Fernet(key256)
    m2 = f2.encrypt(b"A really secret message.  Not for prying eyes.")
    m2d = f2.decrypt(m2).decode('utf-8')

    count += 1
    print ("Iteration Count: {0}".format(count))

print(count)

