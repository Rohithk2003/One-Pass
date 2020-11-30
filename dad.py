import glob
import os

a = glob.glob("*.bin.fenc")
for i in a:
    os.remove(i)
