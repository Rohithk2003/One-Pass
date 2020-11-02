import pickle
f = open('ss.bin.fenc','rb')
line = pickle.load(f)
print(line)
