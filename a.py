import pickle
f = open('hello.bin','wb')
l = [1,2,3,4,5,5,5,5,4,4,34,4,4,4]
pickle.dump(l,f)
f.close()
password = 'te'
buffersize = 64*1024

pyAesCrypt.encryptFile('hello.bin','hello.bin.aes',password,buffersize)

pyAesCrypt.decryptFile('hello.bin.aes','hello1.bin',password,buffersize)
f1 = open('hello1.bin','rb')
line = pickle.load(f1)
print(line)

