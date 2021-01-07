import os,glob
for i in glob.glob("*.bin.aes"):
    os.remove(i)
