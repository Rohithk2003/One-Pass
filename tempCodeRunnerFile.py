
''' to remove all decrypted files
the glob function returns a list of files ending with .decrypted.bin'''
list_file = glob.glob("*decrypted.bin")
for i in list_file:
    converting_str = str(i)
    try:
        os.remove(converting_str)
    except:
        pass
