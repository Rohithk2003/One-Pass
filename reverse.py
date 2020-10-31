import string
def reverse_string(word):
        alphabet_string = string.ascii_lowercase
        alphabet = list(alphabet_string)
        index_replace = 0
        for i in word:
            if i!=' ' and i !='y' and i!='z'  :
                index = alphabet.index(i)
                index_replace += 2
                i = alphabet[index_replace]
            elif i == 'y':
                i = 'a'
            elif i == 'z':
                i = 'b'
        return word
a = 'hi how are you'
reverse_string(a)
