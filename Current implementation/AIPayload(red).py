import random
import string

def mutate_shellcode(shellcode):
    key = ''.join(random.choices(string.ascii_letters, k=4))
    encoded = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(shellcode))
    return f'char payload[] = "{encoded}"; // Decoded at runtime'

shellcode = "\x31\xc0\xb0\x01\x31\xdb\xcd\x80"  # Basic Linux syscall (exit)
print(mutate_shellcode(shellcode))

