from secrets import randbelow
import string

with open('flag', 'rb') as f:
    flag = f.read()
    
fuzzy = [c + randbelow(len(string.ascii_letters)) for c in flag]

print(fuzzy)
