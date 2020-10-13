import pickle
f = open('00.bin','rb')
line = pickle.load(f)
print(line)