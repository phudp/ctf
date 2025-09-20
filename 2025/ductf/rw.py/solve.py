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
b *Py_RunMain
continue
"""
exe = "./rw.py"
#p = process('./fakeobj.py')
#p = gdb.debug('./fakeobj.py', gdbscript = script)
#debug()
# elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = "debug"

s = lambda data: io.send(data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
sla = lambda msg, data: io.sendlineafter(msg, data)
info = lambda msg: log.info(msg)
recvunt = lambda msg: io.recvuntil(msg)
debug = lambda : gdb.attach(io, gdbscript = gdbscript)

# ===================EXPLOIT GOES HERE=======================

io = start(["-q --args python3-dbg"])

#p = process('./fakeobj.py')
# io = gdb.debug('./rw.py', gdbscript = gdbscript)
# debug()

io.interactive()

