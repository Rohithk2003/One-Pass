import hashlib
a = hashlib.sha512(b"test1").hexdigest()
d = hashlib.sha512(b"test1").hexdigest()
print(a)