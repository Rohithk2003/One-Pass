import pickle 
with open(f'rohithdecrypted.bin','r') as f:
    d = pickle.load(f)
    print(d)