from cryptography.fernet import Fernet

print('\n##### Demo Script Using "cryptography" Library #####\n')

message = 'A really secret message. Not for prying eyes.'

key = Fernet.generate_key()
print(f'Key: {key}\n')

f = Fernet(key)
encrypted = f.encrypt(bytes(message, 'utf-8'))
print(f'Encrypted Message: {encrypted}\n')

decrypted = f.decrypt(encrypted).decode('utf-8')
print(f'Decrypted Message: {decrypted}\n')
