import os
import glob
def delete_file():
    list_file = glob.glob("*decrypted.bin")
    for i in list_file:
            converting_str = str(i)
            os.remove(converting_str)
