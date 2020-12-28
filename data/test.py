import os
l=os.path.dirname(os.path.realpath(__file__)).split("\\")
pat=''
for i in l:
    if i != 'data':
        pat+=i+'\\'
print(pat)
