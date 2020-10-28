
from simplecrypt import encrypt, decrypt

password = 'sekret'
message = 'this is a secret message'
ciphertext = encrypt(password, message)

print(ciphertext)

