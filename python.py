import ctypes
import os
FILE_ATTRIBUTE_HIDDEN = 0x02

f = open('hi.txt','w')
re = ctypes.windll.kernel32.SetFileAttributesW('hi.txt',FILE_ATTRIBUTE_HIDDEN)
if re:
    print('hidden')
