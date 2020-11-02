import pyAesCrypt
bufferSize = 64*1024
destroy = b'12345'.decode('utf-8')

pyAesCrypt.decryptFile('a.bin.fenc','a.bin',destroy,bufferSize)