import glob
import os
for i in glob.glob('*.fenc') :
    os.remove(i)
os.remove('DATABASE\\users.db')